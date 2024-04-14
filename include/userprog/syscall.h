#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init(void);
void close(int fd);
struct lock filesys_lock;
struct file_descriptor *find_file_descriptor(int fd);

#endif /* userprog/syscall.h */