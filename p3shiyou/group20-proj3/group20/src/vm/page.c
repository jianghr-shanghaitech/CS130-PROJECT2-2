#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "page.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>

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
void spte_grow(struct supp_page_table_entry *spte,void *addr,void *frame)
{
  spte->writable = true;
  spte->addr = pg_round_down (addr);
  spte->type = PAGE_TYPE_FILE;
  spte->frame = frame;
}

void init_spte(struct supp_page_table_entry *spte,struct file *file, off_t ofs, uint8_t *upage, 
                     uint32_t read_bytes, uint32_t zero_bytes,
                     bool writable, int type,size_t page_read_bytes,size_t page_zero_bytes)
{
  spte->type = type;
  spte->file = file;

  spte->offset = ofs;
  spte->addr = upage;

  spte->read_bytes = page_read_bytes;
  spte->zero_bytes = page_zero_bytes;
  
  spte->writable = writable;
  spte->frame = NULL;
  lock_init(&spte->spte_lock);
}

struct supp_page_table_entry *
find_spte(struct hash *supp_page_table, uint8_t *upage)
{
  struct supp_page_table_entry tmp;
  tmp.addr = pg_round_down(upage);
  struct hash_elem *e = hash_find(supp_page_table, &tmp.hash_elem);
  if (!e) return NULL;
  return hash_entry (e, struct supp_page_table_entry, hash_elem);
}

bool
page_lazy_load(struct file *file, off_t ofs, uint8_t *upage, 
                     uint32_t read_bytes, uint32_t zero_bytes,
                     bool writable, int type)
{
  while ((read_bytes + zero_bytes) > 0) 
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      struct supp_page_table_entry *spte = malloc (sizeof (struct supp_page_table_entry));
      if (!spte) return false;

      init_spte(spte,file,ofs,upage,read_bytes,zero_bytes,writable,type,page_read_bytes,page_zero_bytes);

      if (hash_insert (&thread_current()->supp_page_table, &spte->hash_elem))
      {
        free (spte);
        return false;
      }

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

bool stack_grow (void *addr)
{
  struct supp_page_table_entry *spte = malloc (sizeof (struct supp_page_table_entry));

  void *frame = vm_get_frame (PAL_USER, spte);
  if (!frame)
  {
    free (spte);
    return false;
  }

  spte_grow(spte,addr,frame);

  lock_init (&spte->spte_lock);


  if (!install_page (spte->addr, frame, true))
  {
    free (spte);
    vm_free_frame (frame);
    return false;
  }

  if (hash_insert (&thread_current()->supp_page_table, &spte->hash_elem))
  {
    free (spte);
    vm_free_frame (frame);
    return false;
  }
  return true;
}