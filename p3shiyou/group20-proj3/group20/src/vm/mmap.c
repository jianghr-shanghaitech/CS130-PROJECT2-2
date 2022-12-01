#include "mmap.h"
#include "page.h"
#include "frame.h"
#include "swap.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"


void set_mmap(struct vm_mmap *mmap,struct file * file,uint8_t * addr,uint32_t file_size)
{
  mmap->file=file;
  mmap->upage=addr;
  mmap->read_bytes=file_size;
  
  thread_current()->mmap_num+=1;
  mmap->mapping_id=(mapid_t*)thread_current()->mmap_num;
}

void 
free_all_mmap(struct list *mmap_list){
    while(!list_empty(mmap_list)){
        struct vm_mmap *mmap=list_entry(list_begin(mmap_list),struct vm_mmap,elem);
            struct thread *cur_thread = thread_current ();
    struct supp_page_table_entry *spte;
    unsigned i = 0;
    
    while(i < mmap->read_bytes){
        void *upage = mmap->upage + i;
        spte = find_spte (&cur_thread->supp_page_table, upage);
        lock_acquire (&spte->spte_lock);
    
    if (pagedir_is_dirty (cur_thread->pagedir, upage)){ 
      lock_acquire (&file_lock);
      file_write_at (spte->file, upage, spte->read_bytes, spte->offset);
      lock_release (&file_lock);
    }

    if (spte->frame){       
      vm_free_frame (pagedir_get_page (cur_thread->pagedir, spte->addr));
      pagedir_clear_page (cur_thread->pagedir, spte->addr);
    }

    hash_delete (&cur_thread->supp_page_table, &spte->hash_elem); 
    lock_release (&spte->spte_lock);
    i+=PGSIZE;
  }
  file_close (mmap->file);
        list_remove(list_begin(mmap_list));
        free(mmap);
    }
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

    off_t read_success = file_read (spte->file, frame, spte->read_bytes) != (int) spte->read_bytes;
    if(read_success)
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