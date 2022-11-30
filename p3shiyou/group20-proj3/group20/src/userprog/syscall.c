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
static struct file_descriptor *getfile (struct thread *t, int fd);
static void read_buf_page_fault_handler (void *fault_addr);

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
halt(void) {
  shutdown_power_off();
}

//Terminates the current user program, returning status to the kernel.

void
exit(int status) {
  struct thread *cur = thread_current();
  struct thread *parent = thread_get_by_tid(cur->parent_tid);
  cur->exit_code = status;

  /* Give child's exit info to parent */
  if (parent != NULL && !list_empty(&parent->child_thread_list))
  {
    struct list_elem *e = list_begin (&parent->child_thread_list);
    struct child_status *this_child;
    struct list_elem *child_list_end = list_end (&parent->child_thread_list);

    while (e != child_list_end)
    {
      this_child = list_entry (e, struct child_status, child_elem);
      if (this_child->child_tid == cur->tid)
      {
          /* If find the child, set exit_code for this_child */
          this_child->child_exit_code = status;
          break;
      }
      e = list_next (e);
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
  struct file_descriptor *file_desc = malloc (sizeof (struct file_descriptor));
  struct thread *cur = thread_current ();
  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_lock);
  
  if (f == NULL)
    return -1;
  
  file_desc->file = f;
  file_desc->fd = cur->file_num++;
  list_push_back (&cur->fd_list, &file_desc->elem);
  return file_desc->fd;
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
//Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc().

int
read (int fd, void *buffer, unsigned length){
  if (fd == 1)
    return -1;

  void *buf_iter = buffer;
  if (length < PGSIZE)
  {
    /* If the read length is less than PGSIZE, 
       just check the boundaries within the buffer */
    read_buf_page_fault_handler (buf_iter);
    read_buf_page_fault_handler (buf_iter + length);
  }
  else
  { 
    /* If the read length is larger/equal than PGSIZE, 
       check each possible page boundaries */
    buf_iter = pg_round_down (buf_iter);
    unsigned page_count = 0;
    if (length % PGSIZE == 0)
      page_count = length / PGSIZE;
    else
      page_count = length / PGSIZE + 1;
    
    for (int i = 0; i <= page_count; i++)
    {
      read_buf_page_fault_handler (buf_iter);
      buf_iter += PGSIZE;
    }
  }
  
  int size = 0;
  struct file_descriptor *file_desc = getfile (thread_current(), fd);

  if (fd == 0)
  {
    uint8_t *buf = buffer;
    for (unsigned int i = 0; i < length; i++)
      buf[i] = input_getc ();
    return length;
  }
  
  if (file_desc == NULL || file_desc->file == NULL)
    return -1;

  lock_acquire (&file_lock);
  size = file_read (file_desc->file, buffer, length);
  lock_release (&file_lock);
  return size;
}

//Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
int
write (int fd, const void *buffer, unsigned length){
  if (fd == 0)
    return -1;
  else if (fd == 1)
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
    if (file_desc == NULL || file_desc->file == NULL)
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
  unsigned position = -1;
  struct file_descriptor *file_desc = getfile (thread_current(), fd);
  lock_acquire (&file_lock);
  if (file_desc != NULL)
    position = (unsigned) file_tell (file_desc->file);  
  lock_release (&file_lock);
  return position;  
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

void set_mmap(struct vm_mmap *mmap,struct file * file,uint8_t * addr,uint32_t file_size)
{
  mmap->file=file;
  mmap->upage=addr;
  mmap->read_bytes=file_size;
  
  thread_current()->mmap_num+=1;
  mmap->mapping_id=(mapid_t*)thread_current()->mmap_num;
}

mapid_t 
mmap (int fd, void *addr){
  struct thread *cur_thread=thread_current();
  struct file_descriptor *file_desc = getfile (cur_thread, fd);
  uint32_t offset;
  if((fd < 2)  || ((uint32_t)addr % PGSIZE != 0||addr==0) || (file_desc == NULL || file_desc->file == NULL)) return -1;


  lock_acquire (&file_lock);
  struct file *file = file_reopen (file_desc->file);
  lock_release (&file_lock);
  if (file == NULL){
    return -1;
  }

  uint32_t file_size=file_length(file);
  struct vm_mmap *mmap=malloc(sizeof(struct vm_mmap));

  for(offset=0;offset<file_size;offset+=PGSIZE) if (find_spte (&cur_thread->supp_page_table, addr + offset) ||pagedir_get_page (cur_thread->pagedir, addr + offset) || (file_size==0) || (!mmap)) return -1;

  set_mmap(mmap,file,addr,file_size);

  if(page_lazy_load(file,0,addr,file_size,(offset-file_size),true,PAGE_TYPE_MMAP)==false){
    return -1;
  }
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
    if(mmap->mapping_id == mapping){
      break;
    }
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


struct file_descriptor*
getfile (struct thread *t, int fd)
{
  struct list_elem *e = NULL;
  struct list *l = &t->fd_list;
  struct file_descriptor *file_desc = NULL;
  e = list_begin (l);
  while (e != list_end (l))
  {
    file_desc = list_entry (e, struct file_descriptor, elem);
    if (file_desc->fd == fd)
      return file_desc;
    e = list_next (e);
  }
  return NULL;
}

bool load_swap(struct supp_page_table_entry *spte)
{
  if(spte->type == PAGE_TYPE_SWAP)
  {
   void *frame = vm_get_frame (PAL_USER, spte);
   if(!frame) return false;
   
   lock_acquire (&spte->spte_lock);
   
   swap_in (frame, spte->swap_id);
   
   spte->type = PAGE_TYPE_FILE;
   spte->frame = frame;
   
   if (!install_page (spte->addr, frame, spte->writable))
   {
     vm_free_frame (frame);
     return false;
   }
   
   lock_release (&spte->spte_lock);
    return  true;
    }
    else
    {
    void *frame = vm_get_frame (PAL_USER, spte);
    if(!frame) return false;
    lock_acquire (&spte->spte_lock);
    lock_acquire (&file_lock);
    file_seek (spte->file, spte->offset);


    if(file_read (spte->file, frame, spte->read_bytes) != (int) spte->read_bytes)
    {
      vm_free_frame (frame);
      lock_release (&file_lock);
      return false;
    }
    lock_release (&file_lock);
    memset (frame + spte->read_bytes, 0, spte->zero_bytes);
    if (!install_page (spte->addr, frame, spte->writable))
    {
      vm_free_frame (frame);
      return false;
    } 
      spte->frame = frame;
      lock_release (&spte->spte_lock);
     return true;
    }
}

static void
read_buf_page_fault_handler (void *fault_addr)
{
  if (fault_addr == NULL ||!is_user_vaddr (fault_addr))
    exit (-1);

  struct thread *cur = thread_current ();
  bool success = false;

  if (!pagedir_get_page (cur->pagedir, fault_addr))
  {
    struct supp_page_table_entry *spte = find_spte (&cur->supp_page_table, fault_addr);;
    if (spte != NULL) success = load_swap(spte);
    else if  (fault_addr >= intr_f->esp - 32) success = stack_grow (fault_addr);
    if (!success) exit (-1);      
  }
  else
    return;
}
