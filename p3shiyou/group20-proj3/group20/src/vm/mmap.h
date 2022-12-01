#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "filesys/file.h"
#include "vm/page.h"
#include <list.h>

typedef int mapid_t;

struct vm_mmap{
    struct file *file;
    uint8_t *upage;
    uint32_t read_bytes;
    mapid_t mapping_id;
    struct list_elem elem;
};
void set_mmap(struct vm_mmap *mmap,struct file * file,uint8_t * addr,uint32_t file_size);
void free_all_mmap(struct list *mmap_list);
bool load_swap(struct supp_page_table_entry *spte);


#endif