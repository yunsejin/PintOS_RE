/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "lib/string.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	file_page->file = ((struct lazy*)(page->uninit.aux))->file;
	file_page->ofs =((struct lazy*)(page->uninit.aux))->ofs;
	file_page->read_bytes = ((struct lazy*)(page->uninit.aux))->read_bytes;
	file_page->zero_bytes = ((struct lazy*)(page->uninit.aux))->zero_bytes;
	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
	struct lazy* aux = (struct lazy*)page->uninit.aux;

	lock_acquire(&filesys_lock);
	bool result = lazy_load_segment(page, aux);
	lock_release(&filesys_lock);

	return result;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
	struct lazy* aux = (struct lazy*)page->uninit.aux;
	struct file * file = aux->file;

	if(pml4_is_dirty(thread_current()->pml4,page->va)){
		file_write_at(file,page->va, aux->read_bytes, aux->ofs);
		file_write_at(file_page->file,page->va, file_page->read_bytes, file_page->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, false);
	}
	page->frame->page = NULL;
	page->frame = NULL;
	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) 
{
	struct file_page *file_page = &page->file;
		struct lazy* aux = (struct lazy*)page->uninit.aux;
	struct file * file = aux->file;
	 if (pml4_is_dirty(thread_current()->pml4, page->va))
    {
		file_write_at(file,page->va, aux->read_bytes, aux->ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, 0);
    }
    pml4_clear_page(thread_current()->pml4, page->va);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {


	struct file* new_file = file_reopen(file);
	if(new_file == NULL){
		return NULL;
	}

	void* return_address = addr;
	
	size_t read_bytes;
	if (file_length(new_file) < length){
		read_bytes = file_length(new_file);
	} else {
		read_bytes = length;
	}

	size_t zero_bytes = PGSIZE - (read_bytes%PGSIZE);
	
	ASSERT (pg_ofs (addr) == 0);
	ASSERT (offset % PGSIZE == 0);
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
			/* Do calculate how to fill this page.
			* We will read PAGE_READ_BYTES bytes from FILE
			* and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy* file_lazy = (struct lazy*)malloc(sizeof(struct lazy));
		file_lazy->file = new_file;
		file_lazy->ofs = offset;
		file_lazy->read_bytes = page_read_bytes;
		file_lazy->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, file_lazy)){
			return NULL;
		}		

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return return_address;
}

void
do_munmap (void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = spt_find_page(spt, addr);

	int page_count;
	if (file_length(&page->file)%PGSIZE != 0){
 	    page_count = file_length(&page->file) + PGSIZE;
	} else {
		page_count = file_length(&page->file);
	}

    for (int i = 0; i < page_count/PGSIZE; i++)
    {
        if (page)
            destroy(page);
        addr += PGSIZE;
        page = spt_find_page(spt, addr);
    }
}
