#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/user/syscall.h"


struct lock file_lock;  

void syscall_init (void);

bool validate_addr(void *ptr);
bool validate_string(char *str);

#endif /* userprog/syscall.h */