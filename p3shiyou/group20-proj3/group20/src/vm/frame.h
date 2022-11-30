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
  void *frame;                            
  
  struct list_elem elem;
  struct supp_page_table_entry *spte;  
  tid_t owner;                            
  

  bool free;
  int time;                               
};

void vm_frame_table_init (void);
void *vm_get_frame (enum palloc_flags, struct supp_page_table_entry *);
void vm_free_frame (void *frame);
#endif