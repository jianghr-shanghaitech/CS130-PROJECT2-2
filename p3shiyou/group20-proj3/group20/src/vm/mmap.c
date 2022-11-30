#include "mmap.h"
#include "page.h"
#include "frame.h"
#include "swap.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
//free the first mmap until the mmap_list is empty

void 
free_all_mmap(struct list *mmap_list){
    while(!list_empty(mmap_list)){
        struct vm_mmap *mmap=list_entry(list_begin(mmap_list),struct vm_mmap,elem);
            struct thread *cur_thread = thread_current ();
    struct supp_page_table_entry *spte;
    unsigned i = 0;
    
    while(i <  mmap->read_bytes){
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