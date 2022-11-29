#include "mmap.h"
#include "page.h"
#include "frame.h"
#include "swap.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

void 
free_single_mmap(struct vm_mmap *mmap){
    struct thread *cur_thread = thread_current ();
    struct supp_page_table_entry *spte;
    
    for(unsigned i = 0; i <  mmap->read_bytes; i+=PGSIZE){
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
  }
  file_close (mmap->file);
}


void 
free_all_mmap(struct list *mmap_list){
    while(!list_empty(mmap_list)){
        struct list_elem *iter=list_begin(mmap_list);
        struct vm_mmap *mmap=list_entry(iter,struct vm_mmap,elem);
        free_single_mmap(mmap);
        list_remove(iter);
        free(mmap);
    }
}