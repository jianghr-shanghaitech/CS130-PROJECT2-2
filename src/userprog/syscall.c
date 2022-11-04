#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>
# define USER_VADDR_BOUND (void*) 0x08048000
static void (*syscalls[15])(struct intr_frame *);

void halt(); /* syscall halt. */
void exit (int status); /* syscall exit. */
int exec (const char *cmd_line); /* syscall exec. */

bool create (const char *file, unsigned initial_size); /* syscall create */
bool remove (const char *file); /* syscall remove */
int open (const char *file);/* syscall open */
int wait (int pid); /*syscall wait */
void filesize(struct intr_frame* f);/* syscall filesize */
void read(struct intr_frame* f);  /* syscall read */
void write(struct intr_frame* f); /* syscall write */
void seek(struct intr_frame* f); /* syscall seek */
void tell(struct intr_frame* f); /* syscall tell */
void close(struct intr_frame* f); /* syscall close */
static void syscall_handler (struct intr_frame *);
struct thread_file * find_file_id(int fd);
static void check_uadd (const uint8_t *uaddr); // check useraddress validation

void read_user(void* ptr, void* rt, size_t size); // read from user stack
void invalid_exit(); // handle excption exit cases
static int get_user (const uint8_t *uaddr);

struct lock syscall_lock;


static void check_uadd(const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user(uaddr) == -1)
    invalid_exit();
}


void
syscall_init (void)
{
  lock_init(&syscall_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscalls[SYS_HALT] = &halt;
  syscalls[SYS_EXIT] = &exit;
  syscalls[SYS_EXEC] = &exec;
  syscalls[SYS_WAIT] = &wait;
  syscalls[SYS_CREATE] = &create;
  syscalls[SYS_REMOVE] = &remove;
  syscalls[SYS_OPEN] = &open;
  syscalls[SYS_WRITE] = &write;
  syscalls[SYS_SEEK] = &seek;
  syscalls[SYS_TELL] = &tell;
  syscalls[SYS_CLOSE] =&close;
  syscalls[SYS_READ] = &read;
  syscalls[SYS_FILESIZE] = &filesize;
}

static int get_user (const uint8_t *uaddr)
{
  // ensure uaddr under PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
  return result;
}

void * ptr2(const void *vaddr)
{ 
  if (!is_user_vaddr(vaddr) || (!pagedir_get_page (thread_current()->pagedir, vaddr)))
  {
    thread_current()->exit_status = -1;
    thread_exit ();
  }
  uint8_t *check_byteptr = (uint8_t *) vaddr;
  uint8_t i = 0;
  while (i < 4) 
  {
    auto byteptr = get_user(check_byteptr + i);
    if (byteptr == -1)
    {
      thread_current()->exit_status = -1;
      thread_exit ();
    }
    i++;
  }
  return pagedir_get_page (thread_current()->pagedir, vaddr);
}


void halt () {shutdown_power_off();}

void exit (int status)
{
  thread_current()->exit_status = status;
  thread_exit ();
}

int exec (const char *cmd_line)
{
  check_uadd(cmd_line);
  lock_acquire(&syscall_lock);
  int pid = process_execute(cmd_line);
  lock_release(&syscall_lock);
  return pid;
}


int wait (int pid)
{
  return process_wait(pid);
}


bool create (const char *file, unsigned initial_size)
{
  check_uadd(file);
  lock_acquire(&syscall_lock);
  bool success = filesys_create (file, initial_size);
  lock_release(&syscall_lock);
  return success;
}

bool remove (const char *file)
{
  check_uadd(file);
  bool rt;
  lock_acquire(&syscall_lock);
  rt = filesys_remove (file);
  lock_release(&syscall_lock);
  return rt;
}

int open (const char *file)
{
  check_uadd(file);
  lock_acquire(&syscall_lock);
  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) return -1;
}
void 
write (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 7);
  ptr2 (*(user_ptr + 6));
  *user_ptr++;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (*user_ptr == 1) {
    putbuf(buffer,size);
    f->eax = size;
  }
  else
  {
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f ();
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f ();
      return;
    } 
    f->eax = 0;
  }
}
/* Do system seek, by calling the function file_seek() in filesystem */
void 
seek(struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 5);
  *user_ptr++;
  struct thread_file *file_temp = find_file_id (*user_ptr);
  if (file_temp)
  {
    acquire_lock_f ();
    file_seek (file_temp->file, *(user_ptr+1));
    release_lock_f ();
  }
}

void 
tell (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file *thread_file_temp = find_file_id (*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f ();
    f->eax = file_tell (thread_file_temp->file);
    release_lock_f ();
  }else{
    f->eax = -1;
  }
}

void 
close (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  ptr2 (user_ptr + 1);
  *user_ptr++;
  struct thread_file * opened_file = find_file_id (*user_ptr);
  if (opened_file)
  {
    acquire_lock_f ();
    file_close (opened_file->file);
    release_lock_f ();
    list_remove (&opened_file->file_elem);
    free (opened_file);
  }
}


void 
filesize (struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  ptr2 (f->esp + 1);
  *user_ptr++;
  struct thread_file * file_temp = find_file_id (*user_ptr);
  auto file = file_temp->file;
  if (file_temp)
  {
    acquire_lock_f ();
    f->eax = file_length (file);
    release_lock_f ();
    return;
  } 
  f->eax = -1;
}

bool 
is_valid_pointer (void* esp,uint8_t argc){
  for (uint8_t i = 0; i < argc; ++i)
  {
    if((!is_user_vaddr (esp)) || 
      (pagedir_get_page (thread_current()->pagedir, esp)==NULL)){
      return false;
    }
  }
  return true;
}


void 
read (struct intr_frame* f)
{
  uint32_t *user_ptr = f->esp;
  *user_ptr++;
  int fd = *user_ptr;
  int i;
  uint8_t * buffer = (uint8_t*)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  if (!is_valid_pointer (buffer, 1) || !is_valid_pointer (buffer + size,1)){
      thread_current()->exit_status = -1;
  thread_exit ();
  }
  if (!fd) 
  {
    for (i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
    return;
  }
  struct thread_file * thread_file_temp = find_file_id (*user_ptr);
  auto file = thread_file_temp->file;
  if (thread_file_temp)
  {
    acquire_lock_f ();
    f->eax = file_read (file, buffer, size);
    release_lock_f ();
    return;
  } 
  f->eax = -1;
}

struct thread_file * 
find_file_id (int file_id)
{
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  e = list_begin (files);
  while ( e != list_end (files))
  {
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    auto fd = thread_file_temp->fd;
    if (file_id == fd)
    return thread_file_temp;
    e = list_next (e);
  }
  return false;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
    int * p = f->esp;
    ptr2 (p + 1);
    int type = * (int *)f->esp;
    if(type <= 0 || type >= 15){
    thread_current()->exit_status = -1;
    thread_exit ();
  }
  switch(type){
    case SYS_HALT:{
      halt();
      break;
    }
    
    case SYS_EXIT:{
      int status;
      read_user(f->esp + 4, &status, sizeof(int));
      exit(status);
      break;
    }

    case SYS_EXEC:{
      void* cmdline;
      read_user(f->esp + 4, &cmdline, sizeof(cmdline));
      int pid = exec(cmdline);
      f->eax = (uint32_t) pid;
      break;
    }

    case SYS_WAIT:{
      int pid;
      read_user(f->esp + 4, &pid, sizeof(int));
      f->eax = wait(pid);
      break;
    }

    case SYS_CREATE:{
      const char* file;
      unsigned size;
      read_user(f->esp + 4, &file, sizeof(file));
      read_user(f->esp + 8, &size, sizeof(size));

      f->eax = create(file, size);
      break;
    }
    
    case SYS_REMOVE:{
      const char* file;
      read_user(f->esp + 4, &file, sizeof(file));
      f->eax = remove(file);
      break;
    }
    
    case SYS_OPEN:{
      const char* file;
      read_user(f->esp + 4, &file, sizeof(file));
      f->eax = open(file);
      break;
    }
    // case SYS_FILESIZE:
    // case SYS_READ:
    // case SYS_WRITE:
    // case SYS_SEEK:
    // case SYS_TELL:
    // case SYS_CLOSE:
    default:
      syscalls[type](f);
      // exit_special ();
      break;
  }
}
//   int * p = f->esp;
//   ptr2 (p + 1);
//   int type = * (int *)f->esp;
//   if(type <= 0 || type >= 15){
//     thread_current()->exit_status = -1;
//     thread_exit ();
//   }
//   if (type == 1)
//   {
//     syscalls[type](f->esp);
//   }
//   syscalls[type](f);
// }

void invalid_exit(){
  if(lock_held_by_current_thread(&syscall_lock))
    lock_release(&syscall_lock);
  thread_current()->exit_status = -1;
  thread_exit();
}

void read_user(void* ptr, void* rt, size_t size){
  for(size_t i=0; i<size; i++) {
    int value = get_user(ptr + i);
    if(value == -1) // segfault
      invalid_exit();
    
    *(char*)(rt + i) = (char) value;
  }
}
