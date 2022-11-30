#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "frame.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "swap.h"

#define STACK_LIMIT (1 << 23)

#define PAGE_TYPE_FILE 0
#define PAGE_TYPE_SWAP 1
#define PAGE_TYPE_MMAP 2



struct supp_page_table_entry
{
    struct file *file;            
    off_t offset;                 
    void *addr;                   
    uint32_t read_bytes;          
    uint32_t zero_bytes;          
    bool writable;                
    size_t swap_id;               
    struct lock spte_lock;        
    int type;                    
    void* frame;                  
    struct hash_elem hash_elem;   
};

void supp_page_table_init(struct hash *);
struct supp_page_table_entry *find_spte (struct hash *, uint8_t *);

bool page_lazy_load (struct file *, off_t, uint8_t *, uint32_t, uint32_t, bool, int);
bool page_swap_in (struct supp_page_table_entry *);

bool stack_grow (void *);
#endif