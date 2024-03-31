#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/threads/init.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "include/lib/stdio.h"
#include "include/lib/string.h"
#include "include/lib/user/syscall.h"
#include "devices/input.h"
#include "threads/palloc.h"

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *file_addr);
void check_buffer(void *buffer);
int process_add_file(struct file *file);
struct file_descriptor *find_file_descriptor(int fd);

static struct intr_frame *frame;
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) 
{
	frame = f;
	int sys_num = f->R.rax;
	switch(sys_num)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:	
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;	
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;	
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;	
		case SYS_CLOSE:
			close(f->R.rdi);
			break;	

		default:
			break;
	}
}

void halt (void) 
{	
	power_off();
}

void exit (int status)
{	
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

pid_t fork (const char *thread_name)
{	
	return process_fork(thread_name,frame);
}

int exec (const char *cmd_line)
{
	check_address(cmd_line);

	char *cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if(cmd_line_copy == NULL)
		exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	if(process_exec(cmd_line_copy) == -1)
		exit(-1);
}

int wait (pid_t pid)
{
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{	
	check_address(file);
	return filesys_create (file, initial_size);
}

int open (const char *file)
{
	check_address(file);
	struct file *file_open = filesys_open(file);
	if(file_open == NULL)
		return -1;

	int	fd = process_add_file(file_open);
	if(fd == -1)
		file_close(file_open);

	return fd;
}

int filesize (int fd)
{
	struct file_descriptor *curr_fd = find_file_descriptor(fd);
	if(curr_fd == NULL) return -1;
	return file_length(curr_fd->file);
}

int read (int fd, void *buffer, unsigned length)
{
	check_buffer(buffer);
	
	int byte = 0;
	char *ptr = (char *)buffer;
	if(fd == 0)
	{
		for(int i = 0; i < length; i++)
		{
			*ptr++ = input_getc();
			byte ++;
		}
	}
	else
	{
		struct file_descriptor *curr_fd = find_file_descriptor(fd);
		if(curr_fd == NULL) return -1;
		byte = file_read(curr_fd->file, buffer, length);
	}
	return byte;
}

int write (int fd, const void *buffer, unsigned length)
{
	check_buffer(buffer);
	int byte = 0;
	if(fd == 1)
	{
		putbuf(buffer, length);
		byte = length;
	}else
	{
		struct file_descriptor *curr_fd = find_file_descriptor(fd);
		if(curr_fd == NULL) return NULL;
		byte = file_write(curr_fd->file, buffer, length);
	}
	return byte;
}

void seek (int fd, unsigned position)
{
	struct file_descriptor *curr_fd = find_file_descriptor(fd);
	if(curr_fd == NULL)
		return NULL;
	file_seek(curr_fd->file, position);
}
unsigned tell (int fd)
{
	struct file_descriptor *curr_fd = find_file_descriptor(fd);
	if(curr_fd == NULL)
		return NULL;
	return file_tell(curr_fd->file);
}

void close (int fd)
{
	struct file_descriptor *curr_fd = find_file_descriptor(fd);
	if(curr_fd == NULL) return NULL;

	list_remove(&curr_fd->fd_elem);
	file_close(curr_fd->file);
	free(curr_fd);
}

bool remove (const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

void check_address(void *file_addr)
{
	struct thread *t = thread_current();
	if(file_addr == "\0" || file_addr == NULL || !is_user_vaddr(file_addr) || pml4_get_page(t->pml4, file_addr) == NULL)
		exit(-1);
}

void check_buffer(void *buffer)
{
	struct thread *t = thread_current();
	if(!is_user_vaddr(buffer) || pml4_get_page(t->pml4, buffer) == NULL)
		exit(-1);
}

int process_add_file(struct file *file)
{
	struct thread *curr = thread_current();
	struct file_descriptor *cur_fd = malloc(sizeof(struct file_descriptor));
	struct list *fd_list = &thread_current()->fd_list;
	
	cur_fd->file = file;
	cur_fd->fd_num = (curr->last_create_fd)++;	
	
	list_push_back(fd_list, &cur_fd->fd_elem);

	return cur_fd->fd_num; 
}

struct file_descriptor *find_file_descriptor(int fd)
{
	struct list *fd_list = &thread_current()->fd_list;
	if(list_empty(fd_list)) return NULL;

	struct file_descriptor *file_descriptor;
	struct list_elem *cur_fd_elem = list_begin(fd_list);

	while(cur_fd_elem != list_end(fd_list))
	{
		file_descriptor = list_entry(cur_fd_elem, struct file_descriptor, fd_elem);

		if(file_descriptor->fd_num == fd)
		{
			return file_descriptor;	
		}			
		cur_fd_elem = list_next(cur_fd_elem);
	}
	return NULL;
}