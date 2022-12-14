#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *file_name, void (**eip) (void), void **esp);
void free_child_list (struct thread * f);
void free_opened_file (struct thread *f);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);  /* New mem, will be freed below or in start_process() */
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Extract the first arg - name of this thread */
  char *program_name, *save_ptr;
  program_name = palloc_get_page(0);  /* New mem, will be freed after thread_create() */
  if (program_name == NULL)
  {
    palloc_free_page (fn_copy);   /* If fail, free memory */
    return TID_ERROR;
  }
  strlcpy (program_name, file_name, PGSIZE);
  program_name = strtok_r ((char *)program_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. Obtains tid of the new thread */
  tid = thread_create (program_name, PRI_DEFAULT, start_process, fn_copy);

  /* Free mem */
  palloc_free_page (program_name);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
  }
  else
  {
    /* Setup initial infomation for the child thread */
    struct thread* new_thread = thread_get_by_tid(tid);
    new_thread->parent_tid = thread_current ()->tid;
    
    struct child_status *child = malloc (sizeof (struct child_status)); /* New mem, will be freed in process_exit() */
    if (child != NULL)
    { 
      child->child_tid = tid;
      child->child_exit_code = 0;
      child->child_waited = false;
      sema_init (&child->child_wait_sema, 0);  /* Note that initial sema is 0 */
      list_push_back (&thread_current ()->child_thread_list, &child->child_elem);
    }
    else
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }
  }
  
  return tid;
}

unsigned
page_hash_func(const struct hash_elem *e, void *aux)
{
  const struct supp_page_table_entry * spte = hash_entry (e, struct supp_page_table_entry, hash_elem);
  return hash_bytes (&spte->addr, sizeof (spte->addr));
}

bool
page_hash_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct supp_page_table_entry *a = hash_entry (a_, struct supp_page_table_entry, hash_elem);
  const struct supp_page_table_entry *b = hash_entry (b_, struct supp_page_table_entry, hash_elem);
  return a->addr < b->addr;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

    hash_init(&thread_current()->supp_page_table, page_hash_func, page_hash_less, NULL);
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  struct thread *parent_thread = thread_get_by_tid(thread_current()->parent_tid);
  if (success)
    parent_thread->load_state = LOAD_SUCCESS;
  else
    parent_thread->load_state = LOAD_FAIL;
  sema_up(&(parent_thread->load_sema));  

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
    thread_current()->exit_code = -1;
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *cur = thread_current ();

  if (child_tid == TID_ERROR)
  {
    return -1;
  }
  else
  {
    if (list_empty (&cur->child_thread_list))
      return -1;
    else 
    {
      struct list_elem *e = list_begin (&cur->child_thread_list);
      struct child_status *child;
      struct list_elem *child_list_end = list_end (&cur->child_thread_list);

      while (e != child_list_end)
      {
        child = list_entry (e, struct child_status, child_elem);
        if (child->child_tid == child_tid && !child->child_waited)
        {
          sema_down (&child->child_wait_sema);
          child->child_waited = true;

          return child->child_exit_code;
        }
        else if (child->child_tid == child_tid && child->child_waited)
        {
          return -1;
        }
        e = list_next(e);
      }
    }
    return -1; 
  }
}

bool free_all()
{
  free_child_list (thread_current ());
  free_opened_file (thread_current ());
  free_all_mmap (&thread_current ()->mmap_list);
}

void
process_exit (void)
{
  uint32_t *pd;

  printf("%s: exit(%d)\n", thread_current ()->name, thread_current ()->exit_code);

  struct thread *parent_thread = thread_get_by_tid(thread_current ()->parent_tid);
  if (parent_thread)
  {
    if(list_empty (&parent_thread->child_thread_list))
    {
      return;
    }
    else 
    {
      struct list_elem *e = list_begin (&parent_thread->child_thread_list);
      struct child_status *child;
      struct list_elem *child_list_end = list_end (&parent_thread->child_thread_list);

      while (e != child_list_end)
      {
        child = list_entry (e, struct child_status, child_elem);
        if (child->child_tid == thread_current ()->tid)
        {
          sema_up (&child->child_wait_sema);
          break;
        }
        e = list_next (e);
      }
    }
  }

  if (thread_current ()->running_file != NULL)
  {
    file_allow_write (thread_current ()->running_file);
    file_close (thread_current ()->running_file);
  }

  free_all();

void
page_hash_free (struct hash_elem *e, void *aux UNUSED)
{
  struct supp_page_table_entry* spte = hash_entry (e, struct supp_page_table_entry, hash_elem);
  if(spte->frame)
    vm_free_frame(spte->frame);
  free (spte);
}

  hash_destroy (&thread_current ()->supp_page_table, page_hash_free);


  pd = thread_current ()->pagedir;
  if (pd != NULL) 
  {
      thread_current ()->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* DONT MESS UP WITH file_name */
  char *fn_copy, *saved_ptr;
  fn_copy = malloc(strlen(file_name) + 1);
  strlcpy(fn_copy, file_name, strlen(file_name) + 1);
  fn_copy = strtok_r(fn_copy, " ", &saved_ptr);

  /* Open executable file. */
  file = filesys_open(fn_copy);
  free(fn_copy);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 /* We arrive here whether the load is successful or not. */
 done:
  /* The loaded file cannot be written when running */
  if (success)
  {
    t->running_file = file;
    file_deny_write (file);
  }
  else
    file_close (file);
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  return page_lazy_load(file, ofs, upage, read_bytes, zero_bytes, writable, PAGE_TYPE_FILE);
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *file_name) 
{
  bool success = false;

  success = stack_grow (((uint8_t *) PHYS_BASE) - PGSIZE);
  if (success)
    *esp = PHYS_BASE;

  /* DONT MESS UP WITH file_name */
  char *fn_copy = malloc(strlen(file_name)+1);
  strlcpy (fn_copy, file_name, strlen(file_name)+1);

  /* Setup the stack of parameters */
  char *program_name, *argv, *save_ptr;
  char *argvs[128];
  int argc = 1;
  program_name = strtok_r (fn_copy, " ", &save_ptr);
  /* push program name. */
  *esp -= strlen(program_name) + 1;
  memcpy (*esp, program_name, strlen (program_name) + 1);
  argvs[0] = (char*) (*esp);
  /* push each argument. */
  for (argv = strtok_r (NULL, " ", &save_ptr); argv != NULL;
        argv = strtok_r (NULL, " ", &save_ptr))
  {
    *esp -= strlen(argv) + 1;
    memcpy (*esp, argv, strlen (argv) + 1);
    argvs[argc] = (char*) (*esp);
    ++argc;
  }
  /* alignment to 4*/
  while((uint32_t)(*esp) % 4 != 0){
    *esp -= 1;
    *(char*)(*esp) = (char)0;
  }
  /* push last \0 of argv */
  *esp -= 4;
  memset (*esp, 0, 4);
  /* push address of every argv */
  for(int i = argc - 1;i >= 0;i--){
    *esp -= 4;
    memcpy (*esp, argvs + i, 4);
  }
  /* push address of argvs */
  *esp -= 4;
  *((char**)(*esp)) = (char*)(*esp) + 4;
  /* push argc */
  *esp -= 4;
  *((int*)(*esp)) = argc;
  /* push return address */
  *esp -= 4;
  *((int*)*(esp)) = 0;

  // hex_dump((uintptr_t)if_.esp, if_.esp, 128, true);

  // free(fn_copy);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Free resources used by child_thread_list */
void 
free_child_list (struct thread *t)
{
  if (t != NULL && !list_empty (&t->child_thread_list))
  {
    struct list_elem *e = list_begin (&t->child_thread_list);
    struct list_elem *end = list_end (&t->child_thread_list);
    struct child_status *child;
    struct list_elem *next;
    while (e != end)
    {
      next = list_next (e);
      child = list_entry (e, struct child_status, child_elem);
      list_remove (e);
      free (child);
      e = next;
    }
  }
  return;
}

/* Free resource used by file */
void 
free_opened_file (struct thread *t)
{
  if (t != NULL && !list_empty(&t->fd_list))
  {
    struct list_elem *e = list_begin (&t->fd_list);
    struct list_elem *end = list_end (&t->fd_list);
    struct file_descriptor *fd;
    struct list_elem *next;
    while (e != end)
    {
      next = list_next (e);
      fd = list_entry (e, struct file_descriptor, elem);
      free(fd->file);
      free (fd);
      e = next;
    }
  }
  return;
}
