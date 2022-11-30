#include "frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "userprog/syscall.h"

struct lock frame_lock;

void *evict_frame (struct supp_page_table_entry *spte);
struct frame_table_entry *find_frame_to_evict();

void 
vm_frame_table_init (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

struct frame_table_entry *find_frame_to_evict()
{
  struct thread *cur_thread = thread_current();
  struct list_elem* e = list_begin(&frame_table);
  struct list_elem* end = list_end(&frame_table);
  int64_t least_recent_time = INT64_MAX;
  struct frame_table_entry *LRU_fte = NULL;

  while(e != end)
  {
    struct frame_table_entry* cur_fte = list_entry (e, struct frame_table_entry, elem);

    if (!pagedir_is_accessed (cur_thread->pagedir, cur_fte->frame))
    {
      return cur_fte;
    }
    if (cur_fte->time < least_recent_time)
    {
      least_recent_time = cur_fte->time;
      LRU_fte = cur_fte;
    }

    e = list_next(e);
  }
  return LRU_fte;
}


void * 
evict_frame(struct supp_page_table_entry *spte)
{
  lock_acquire(&frame_lock);

  struct frame_table_entry *evicted_fte = find_frame_to_evict();

  struct thread *victim_thread = thread_get_by_tid(evicted_fte->owner);
  struct supp_page_table_entry *victim_spte = evicted_fte->spte;
  void *evicted_frame = evicted_fte->frame;
  void *evicted_upage = victim_spte->addr;
  lock_acquire(&spte->spte_lock);
  pagedir_is_dirty (victim_thread->pagedir, evicted_upage);

  if (pagedir_is_dirty (victim_thread->pagedir, evicted_upage) && victim_spte->type == PAGE_TYPE_MMAP)
  {
    lock_acquire (&file_lock);
    file_write_at (victim_spte->file, evicted_upage,
                    victim_spte->read_bytes, victim_spte->offset);
    lock_release (&file_lock);
  } 
  else
  {
    victim_spte->type = PAGE_TYPE_SWAP;
    victim_spte->frame = NULL;
    victim_spte->swap_id = swap_out (evicted_frame);
  }

  pagedir_clear_page (victim_thread->pagedir, evicted_upage);
  memset (evicted_frame, 0, PGSIZE);

  evicted_fte->owner = thread_tid();
  evicted_fte->spte = spte;
  evicted_fte->time = timer_ticks();
  lock_release(&spte->spte_lock);
  lock_release(&frame_lock);
  return evicted_frame;
}

void set_ft(struct frame_table_entry *ft_entry,void *frame,struct supp_page_table_entry *spte)
{
  ft_entry->frame = frame;
  ft_entry->owner = thread_tid();
  ft_entry->time = timer_ticks();
  ft_entry->spte = spte;
  ft_entry->free = false;
}

void *
vm_get_frame (enum palloc_flags flags, struct supp_page_table_entry *spte)
{
    if(flags != PAL_USER) return NULL;
    void *frame = palloc_get_page (flags);
    if(!frame) return evict_frame(spte);

    struct frame_table_entry *ft_entry = malloc (sizeof (struct frame_table_entry));
    if (!ft_entry) return NULL;

    set_ft(ft_entry,frame,spte);

    lock_acquire(&frame_lock);
    list_push_back(&frame_table, &ft_entry->elem);
    lock_release(&frame_lock);

    return frame;
}

void 
vm_free_frame (void *frame)
{
    if(!frame) return;
    struct list_elem *e = list_begin (&frame_table);
    struct frame_table_entry *ft_entry;

    lock_acquire (&frame_lock);
    while (e != list_end (&frame_table))
    {
        ft_entry = list_entry (e, struct frame_table_entry, elem);
        if (ft_entry->frame == frame)
        {
            ft_entry->free = true;
            break;
        }
        e = list_next (e);
    }
    lock_release (&frame_lock);
}