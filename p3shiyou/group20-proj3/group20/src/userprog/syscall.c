#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"

void halt(); /* syscall halt. */
void exit (int status); /* syscall exit. */
pid_t exec (const char *cmd_line); /* syscall exec. */

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

mapid_t mmap(int fd, void* addr);
void munmap(mapid_t mapping);


void read_user(void* ptr, void* rt, size_t size); // read from user stack
void invalid_exit(); // handle excption exit cases
static int get_user (const uint8_t *uaddr);

void invalid_exit(){
  if(lock_held_by_current_thread(&syscall_init))
    lock_release(&syscall_init);
  thread_current()->status = -1;
  thread_exit();
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

static void check_uadd(const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user(uaddr) == -1)
    invalid_exit();
}

void read_user(void* ptr, void* rt, size_t size){
  for(size_t i=0; i<size; i++) {
    int value = get_user(ptr + i);
    if(value == -1) // segfault
      invalid_exit();
    
    *(char*)(rt + i) = (char) value;
  }
}

static void syscall_handler (struct intr_frame *);
static void buf_exception (void *fault_addr);

static const struct intr_frame *intr_f;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int sys_code = *(int*)f->esp;
  uint32_t *esp = f->esp;
  intr_f = f;
  /* Validate potential addrs */
  check_uadd(esp);
  
  // Choose the syscall according to the type number
  switch (sys_code)
  {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_EXIT:
    {
      int status;
      read_user(f->esp + 4, &status, sizeof(int));
      exit(status);
      break;
    }
    case SYS_EXEC:
    {
      void* cmdline;
      read_user(f->esp + 4, &cmdline, sizeof(cmdline));
      int pid = exec(cmdline);
      f->eax = (uint32_t) pid;
      break;
    }
    case SYS_WAIT:
    {
      int pid;
      read_user(f->esp + 4, &pid, sizeof(int));
      f->eax = wait(pid);
      break;
    }
    case SYS_CREATE:
    {
      const char* file;
      unsigned size;
      read_user(f->esp + 4, &file, sizeof(file));
      read_user(f->esp + 8, &size, sizeof(size));

      f->eax = create(file, size);
      break;
    }
    case SYS_REMOVE:
    {
      const char* file;
      read_user(f->esp + 4, &file, sizeof(file));
      f->eax = remove(file);
      break;
    }
    case SYS_OPEN:
    {
      const char* file;
      read_user(f->esp + 4, &file, sizeof(file));
      f->eax = open(file);
      break;
    }
    case SYS_FILESIZE:
    {
      int fd;
      read_user(f->esp + 4, &fd, sizeof(fd));
      f->eax = filesize(fd);
      break;
    }
    case SYS_READ:
    {
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
      int fd = *(esp + 1);
      unsigned position = *(esp + 2);
      seek (fd, position);
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
     case SYS_MMAP:
    {
      int fd = *(esp + 1);
      void* addr = *(esp + 2);
      f->eax = (uint32_t) mmap(fd, addr);
      break;
    }
    case SYS_MUNMAP:
    {
      mapid_t mapping = *(esp + 1);
      munmap(mapping);
      break;
    }
    default:
    invalid_exit();
      break;
  }
}

//Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h).

void
halt(void) {shutdown_power_off();}

//Terminates the current user program, returning status to the kernel.

void
exit(int status) {
  struct thread *parent = thread_get_by_tid(thread_current()->parent_tid);
  thread_current()->exit_code = status;

  if (parent != NULL && !list_empty(&parent->child_thread_list))
  {
    struct list_elem *begin = list_begin (&parent->child_thread_list);
    struct child_status *child;
    struct list_elem *child_list_end = list_end (&parent->child_thread_list);

    for (struct list_elem *e = begin;e != child_list_end;e = list_next (e))
    {
      child = list_entry (e, struct child_status, child_elem);
      if (child->child_tid == thread_current()->tid)
      {
          child->child_exit_code = status;
          break;
      }
    }
  }
  thread_exit ();
}

//Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). 

pid_t
exec (const char *cmd_line)
{
  check_uadd(cmd_line);
  lock_acquire(&file_lock);
  int pid = process_execute(cmd_line);
  lock_release(&file_lock);
  sema_down(&(thread_current()->load_sema));
  auto state = thread_current()->load_state;
  if (state == LOAD_SUCCESS) return pid;
  else    return -1;
}

//Waits for a child process pid and retrieves the child's exit status.

int
wait (pid_t pid){
  return process_wait (pid);
}

//Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 

bool
create (const char *file, unsigned initial_size){
  check_uadd(file);
  lock_acquire (&file_lock);
  bool status = filesys_create (file, initial_size);
  lock_release (&file_lock);
  return status;
}

//Deletes the file called file. Returns true if successful, false otherwise.

bool
remove (const char *file){
  check_uadd(file);
  bool status = false;
  lock_acquire (&file_lock);
  status = filesys_remove (file);
  lock_release (&file_lock);
  return status;
}

//Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.

int
open (const char *file){
  check_uadd(file);
  lock_acquire(&file_lock);
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) return -1;
  struct file* file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&file_lock);
    return -1;
  }

  struct thread * t = thread_current();
  if (file_opened)
  {
    struct thread_file *thread_file_temp = malloc(sizeof(struct thread_file));
    thread_file_temp->fd = t->file_num++;
    thread_file_temp->file = file_opened;
    list_push_back (&t->fd_list, &thread_file_temp->file_elem);
    lock_release (&file_lock);
    return thread_file_temp->fd;;
  }
  else{
    lock_release (&file_lock);
    return -1;
  }
}

//Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc().

int
read (int fd, void *buffer, unsigned length)
{
  if (fd == 1)
    return -1;
  else if (fd == 0)
  {
    uint8_t *buf = buffer;
    for (unsigned int i = 0; i < length; i++)
      buf[i] = input_getc ();
    return length;
  }
  int i = 0; 

  void *buf_iter = buffer;
  if (length < PGSIZE) buf_exception (buf_iter);
  else
  { 
    buf_iter = pg_round_down (buf_iter);
    unsigned page_count = 0;
    page_count = (length % PGSIZE == 0) ?  (length / PGSIZE) :  (length / PGSIZE + 1);
    
    while (i <= page_count)
    {
      buf_exception (buf_iter);
      buf_iter += PGSIZE;
      i++;
    }
  }
  
  struct file_descriptor *file_desc = getfile (thread_current(), fd);

  
  if (!file_desc || !file_desc->file)
    return -1;

  lock_acquire (&file_lock);
  int size = file_read (file_desc->file, buffer, length);
  lock_release (&file_lock);
  return size;
}

//Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
int
write (int fd, const void *buffer, unsigned length){
  if (fd == 1)
  {
    check_uadd(buffer);
    int size = 0 ;
    putbuf ((char *)buffer, (size_t)length);
    return length;
  }
  else
  {
    check_uadd(buffer);
    int size = 0 ;
    struct file_descriptor* file_desc = getfile (thread_current(), fd);
    if (!file_desc || !file_desc->file)
    return -1;
  
    lock_acquire (&file_lock);
    size = file_write (file_desc->file, buffer, length);
    lock_release (&file_lock);

    return size;
  }

}

//Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)

void 
seek (int fd, unsigned position)
{
  struct file_descriptor *file_desc = getfile (thread_current(), fd);
  lock_acquire (&file_lock);
  if (file_desc != NULL)
    file_seek (file_desc->file, position);
  lock_release (&file_lock);
}

//Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.

unsigned 
tell (int fd)
{
  struct thread_file *thread_file_temp = getfile (thread_current(),fd);
  int rt;
  if (thread_file_temp)
  {
    lock_acquire(&file_lock);
    rt = file_tell (thread_file_temp->file);
    lock_release(&file_lock);
  }else{
    rt = -1;
  }
  return rt;
}

//Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.

void 
close (int fd)
{
  struct file_descriptor *file_desc = getfile (thread_current(), fd);
  lock_acquire (&file_lock);
  if (file_desc != NULL)
    {
      file_close (file_desc->file);
      list_remove (&file_desc->elem);
      free (file_desc);    
    }
  lock_release (&file_lock);
}

//Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
int
filesize (int fd){
  int size = -1;
  struct file_descriptor *file_desc = getfile (thread_current(), fd);
  if (file_desc != NULL)
  {
    lock_acquire (&file_lock);
    size = file_length (file_desc->file);
    lock_release (&file_lock);
  }
  return size;
}

mapid_t 
mmap (int fd, void *addr){
  struct thread *cur_thread=thread_current();
  struct file_descriptor *file_desc = getfile (cur_thread, fd);
  uint32_t offset;
  if((fd - 2 < 0)  || ((uint32_t)addr % PGSIZE != 0||addr==0) || (file_desc == NULL || file_desc->file == NULL)) return -1;

  lock_acquire (&file_lock);
  struct file *file = file_reopen (file_desc->file);
  lock_release (&file_lock);
  if (!file) return -1;


  uint32_t file_size=file_length(file);
  struct vm_mmap *mmap=malloc(sizeof(struct vm_mmap));

  for(offset=0;offset<file_size;offset+=PGSIZE) if (find_spte (&cur_thread->supp_page_table, addr + offset) ||pagedir_get_page (cur_thread->pagedir, addr + offset) || (file_size==0) || (!mmap)) return -1;

  set_mmap(mmap,file,addr,file_size);

  if(!page_lazy_load(file,0,addr,file_size,(offset-file_size),true,PAGE_TYPE_MMAP)) return -1;
  list_push_back(&cur_thread->mmap_list,&mmap->elem);
  auto id = mmap->mapping_id;
  return id;
}

void 
munmap(mapid_t mapping){
  struct thread *cur_thread=thread_current();
  struct list_elem *iter=list_begin(&cur_thread->mmap_list);
  struct vm_mmap *mmap;
  auto end = list_end(&cur_thread->mmap_list);
  while(iter!=end)
  {
    mmap=list_entry(iter,struct vm_mmap,elem);
    if(mmap->mapping_id == mapping) break;
    iter=list_next(iter);
  }
    struct supp_page_table_entry *spte;
    unsigned i = 0;
    
    while(i < mmap->read_bytes)
    {
      void *upage = mmap->upage + i;
      spte = find_spte (&thread_current ()->supp_page_table, upage);
      lock_acquire (&spte->spte_lock);
    
    if (pagedir_is_dirty (thread_current ()->pagedir, upage))
    { 
      lock_acquire (&file_lock);
      file_write_at (spte->file, upage, spte->read_bytes, spte->offset);
      lock_release (&file_lock);
    }

    if (spte->frame){       
      vm_free_frame (pagedir_get_page (thread_current ()->pagedir, spte->addr));
      pagedir_clear_page (thread_current ()->pagedir, spte->addr);
    }

    hash_delete (&thread_current ()->supp_page_table, &spte->hash_elem); 
    lock_release (&spte->spte_lock);
    i+=PGSIZE;
  }
  file_close (mmap->file);
  list_remove(iter);
  free(mmap);
}

static void
buf_exception (void *fault_addr)
{
  if (fault_addr == NULL ||!is_user_vaddr (fault_addr))
    exit (-1);

  bool success = false;

  if (!pagedir_get_page (thread_current ()->pagedir, fault_addr))
  {
    struct supp_page_table_entry *spte = find_spte (&thread_current ()->supp_page_table, fault_addr);;
    if (spte != NULL) success = load_swap(spte);
    else if  (fault_addr >= intr_f->esp - 32) success = stack_grow (fault_addr);
    if (!success) exit (-1);      
  }
}
