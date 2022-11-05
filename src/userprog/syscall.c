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

void halt(); /* syscall halt. */
void exit (int status); /* syscall exit. */
int exec (const char *cmd_line); /* syscall exec. */

bool create (const char *file, unsigned initial_size); /* syscall create */
bool remove (const char *file); /* syscall remove */
int open (const char *file);/* syscall open */
int wait (int pid); /*syscall wait */
int filesize (int fd);/* syscall filesize */
int read (int fd, void *buffer, unsigned size);  /* syscall read */
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position); /* syscall seek */
unsigned tell (int fd); /* syscall tell */
void close(int fd); /* syscall close */
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
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
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
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) return -1;
  struct file* file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&syscall_lock);
    return -1;
  }

  struct thread * t = thread_current();
  if (file_opened)
  {
    struct thread_file *thread_file_temp = malloc(sizeof(struct thread_file));
    thread_file_temp->fd = t->file_fd++;
    thread_file_temp->file = file_opened;
    list_push_back (&t->files, &thread_file_temp->file_elem);
    lock_release (&syscall_lock);
    return thread_file_temp->fd;;
  }
  else{
    lock_release (&syscall_lock);
    return -1;
  }
}

int write (int fd, const void *buffer, unsigned size)
{
  int rt;
  if (fd == 1) {
    putbuf(buffer,size);
    return size;
  }
  else
  {
    struct thread_file * thread_file_temp = find_file_id (fd);
    if (thread_file_temp)
    {
      lock_acquire(&syscall_lock);
      rt = file_write (thread_file_temp->file, buffer, size);
      lock_release(&syscall_lock);
    } 
    else{
      rt = 0;
    }
  }
  return rt;
}
/* Do system seek, by calling the function file_seek() in filesystem */
void seek(int fd, unsigned position)
{
  struct thread_file *file_temp = find_file_id (fd);
  if (file_temp)
  {
    lock_acquire(&syscall_lock);
    file_seek (file_temp->file, position);
    lock_release(&syscall_lock);
  }
}

unsigned tell (int fd)
{
  struct thread_file *thread_file_temp = find_file_id (fd);
  int rt;
  if (thread_file_temp)
  {
    lock_acquire(&syscall_lock);
    rt = file_tell (thread_file_temp->file);
    lock_release(&syscall_lock);
  }else{
    rt = -1;
  }
  return rt;
}

void close (int fd)
{
  struct thread_file * opened_file = find_file_id (fd);
  if (opened_file)
  {
    lock_acquire(&syscall_lock);
    file_close (opened_file->file);
    lock_release(&syscall_lock);
    list_remove (&opened_file->file_elem);
    free (opened_file);
  }
}


int filesize (int fd){
  struct thread_file * file_temp = find_file_id (fd);
  auto file = file_temp->file;
  int rt;
  if (file_temp)
  {
    lock_acquire(&syscall_lock);
    rt = file_length (file);
    lock_release(&syscall_lock);
  }
  else rt = -1;
  return rt;
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


int read (int fd, void *buffer, unsigned size)
{
  int i, rt;
  /* check address bellow PHYS_BASE*/
  check_uadd((uint8_t*)buffer);
  check_uadd((uint8_t*)buffer + size);
  /* check address overflow the page*/
  if(pagedir_get_page (thread_current()->pagedir, buffer)==NULL || pagedir_get_page (thread_current()->pagedir, buffer + size)==NULL){
    invalid_exit();
  }
  lock_acquire(&syscall_lock);
  if(fd == 0){ // stdin
    for(i = 0; i < size; ++i) {
      int temp = put_user(buffer + i, input_getc());
      if(!temp) {
        lock_release (&syscall_lock);
        invalid_exit(); // segfault
      }
      rt = size;
    }
  }
  else{
    struct thread_file * thread_file_temp = find_file_id (fd);
    auto file = thread_file_temp->file;
    if (thread_file_temp)
    {
      rt = file_read (file, buffer, size);
    }
    else rt = -1;
  }
  lock_release(&syscall_lock);
  return rt;
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
    
    case SYS_FILESIZE:{
      int fd;
      read_user(f->esp + 4, &fd, sizeof(fd));
      f->eax = filesize(fd);
      break;
    }
    
    case SYS_READ:{
      int fd;
      void *buffer;
      unsigned size;
      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &buffer, sizeof(buffer));
      read_user(f->esp + 12, &size, sizeof(size));
      f->eax = read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:
      {
        int fd;
        void *buffer;
        unsigned size;
        read_user(f->esp + 4, &fd, sizeof(fd));
        read_user(f->esp + 8, &buffer, sizeof(buffer));
        read_user(f->esp + 12, &size, sizeof(size));
        f->eax = write(fd, buffer, size);
        break;
      }
    case SYS_SEEK:
    {
      int fd;
      unsigned position;
      read_user(f->esp + 4, &fd, sizeof(fd));
      read_user(f->esp + 8, &position, sizeof(position));
      break;
    }
    case SYS_TELL:
    {
      int fd;
      read_user(f->esp + 4, &fd, sizeof(fd));
      f->eax = tell(fd);
      break;
    }
    case SYS_CLOSE:
    {
      int fd;
      read_user(f->esp + 4, &fd, sizeof(fd));
      close(fd);
      break;
    }
    default:
      invalid_exit();
      break;
  }
}

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
