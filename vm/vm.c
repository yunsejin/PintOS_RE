/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/file.h"
#include "vm/inspect.h"
#include "list.h"
#include "include/threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "include/threads/mmu.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

void page_table_kill(struct hash_elem *h, void* aux UNUSED);
static unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
static bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_list);
	lock_init(&page_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *_page = (struct page*)malloc(sizeof(struct page));
		typedef bool (*page_initializer)(struct page *, enum vm_type, void *kva);
		page_initializer init_func = NULL; 
		switch (VM_TYPE(type))
		{
		case VM_ANON:
			init_func = anon_initializer;
			break;
		case VM_FILE:
			init_func = file_backed_initializer;
			break;
		default:
			break;
		}
		uninit_new(_page, upage, init, type, aux, init_func);
		_page->writable = writable;
		/* TODO: Insert the page into the spt. */
		if (spt_insert_page(spt, _page)){
			return true;
		}
		free(_page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *_page;
	/* TODO: Fill this function. */
	_page = (struct page*)malloc(sizeof(struct page));
	_page->va = pg_round_down(va);

	struct hash_elem* e = NULL;

	if (!hash_empty(&spt->spt_hash)){
		e =	hash_find(&spt->spt_hash, &_page->hash_elem);
	}
	free(_page);

	if (e == NULL){
		return NULL;
	}
	_page = hash_entry(e, struct page, hash_elem);

	return _page;
}


/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	/* TODO: Fill this function. */
	struct hash_elem *e = hash_insert(&spt->spt_hash, &page->hash_elem);
	
	if (e == NULL){
		return true;
	} 
	return false;
}


void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->spt_hash, &page->hash_elem);

	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	if(!list_empty(&frame_list)){
		struct list_elem *e;
		while(1){
			e = list_pop_front(&frame_list);
			victim = list_entry(e, struct frame, frame_elem);
			if(victim->page == NULL){
				return victim; 
			}

			if (pml4_is_accessed(thread_current()->pml4, victim->page->va)){
				pml4_set_accessed(thread_current()->pml4, victim->page->va, false);
				lock_acquire(&page_lock);
				list_push_back(&frame_list,e);
				lock_release(&page_lock);
			} else {
				lock_acquire(&page_lock);
				list_push_back(&frame_list, e); 
				lock_release(&page_lock);
				break;
			} 
		}
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (victim != NULL){
		swap_out(victim->page);
	}
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	void* kva = palloc_get_page(PAL_USER);
	if (kva == NULL){	
		frame = vm_evict_frame();
		frame->page = NULL;
		return frame;
	} 
	frame = (struct frame*)malloc(sizeof(struct frame));
	frame->kva = kva; 
	frame->page = NULL; 

	lock_acquire(&page_lock);
	list_push_back(&frame_list, &frame->frame_elem);
	lock_release(&page_lock);


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)){
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if (is_kernel_vaddr(addr) || addr == NULL){

		return false;
	}

	if(not_present){
		struct thread* t = thread_current();
		void* ptr;
		if (user){
			ptr = f->rsp;
		}
		if (!user){
			ptr = t->stack_pointer;
		}

		if ((USER_STACK - (1 << 20) <= ptr && addr < USER_STACK && USER_STACK - (1 <<20) < addr)){
			if (ptr - sizeof(void*) == addr || ptr <= addr){
				vm_stack_growth(pg_round_down(addr));	
			}
		}

		page = spt_find_page(spt , addr);

		if(page == NULL){
			return false;
		}
		if(write && !page->writable){
			return false;
		}
		if (!vm_do_claim_page(page)){
			return false;
		}
		return true;
	}
	return false;
}


/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt,va);
	if (page == NULL){
		return false; 
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *t = thread_current();
	if (pml4_get_page(t->pml4, page->va) != NULL){
		return false; 
	}
	if (!pml4_set_page(t->pml4 , pg_round_down(page->va) , pg_round_down(frame->kva), page->writable)){
		return false;
	}
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */

bool supplemental_page_table_copy(struct supplemental_page_table *dst,
	struct supplemental_page_table *src) {
	struct hash_iterator i;

	hash_first(&i, &src->spt_hash);
	while (hash_next(&i)) {
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		if (src_page->frame == NULL) {
			if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->writable, src_page->uninit.init, src_page->uninit.aux)) {
				return false;
			}
		}
		else {
			enum vm_type src_type = page_get_type(src_page);
			switch (src_type)
			{
			case VM_ANON:
				if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->writable, NULL, NULL)) {
					return false;
				}
				if (!vm_claim_page(src_page->va)) {
					return false;
				}
				break;
			case VM_FILE:
			{
				struct lazy* file_lazy = (struct lazy*)malloc(sizeof(struct lazy));
				file_lazy->file = src_page->file.file;
				file_lazy->ofs = src_page->file.ofs;
				file_lazy->read_bytes = src_page->file.read_bytes;
				file_lazy->zero_bytes = src_page->file.zero_bytes;
				if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->writable, lazy_load_segment, file_lazy)) {
					free(file_lazy);
					return false;
				}
				if (!vm_claim_page(src_page->va)) {
					free(file_lazy);
					return false;
				}
				break;
			}
			default:
				break;
			}
			struct page *dst_page = spt_find_page(dst, src_page->va);
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
	}
	return true;
}
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, page_table_kill);
	
}

void page_table_kill(struct hash_elem *h, void* aux UNUSED){
	const struct page *_page = hash_entry(h, struct page, hash_elem);
	destroy(_page);
	free(_page);
}

static unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
struct page* page = hash_entry(p_,struct page,hash_elem);
	return hash_bytes(&page->va,sizeof(page->va)); 
}

static bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
	struct page* a = hash_entry(a_,struct page,hash_elem);
	struct page* b = hash_entry(b_,struct page,hash_elem);
	return a->va < b->va;
}