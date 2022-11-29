#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "page.h"

typedef int tid_t;
struct list frame_table;

struct frame_table_entry
{
  void *frame;                            /* Actual frame addr */
  int time;                               /* Last access time */
  struct supp_page_table_entry *spte;     /* Corresponding supp_page_table_entry */
  tid_t owner;                            /* The tid of the thread which owns this frame */
  bool free;                              /* If the page is freed, set it to true */
  struct list_elem elem;
};

void vm_frame_table_init (void);
void *vm_get_frame (enum palloc_flags, struct supp_page_table_entry *);
void vm_free_frame (void *frame);
#endif