#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "filesys/file.h"
#include <list.h>

typedef int mapid_t;

struct vm_mmap{
    /*parameter in lazy_load*/
    struct file *file;
    uint8_t *upage;
    uint32_t read_bytes;
    mapid_t mapping_id;
    struct list_elem elem;
};
void free_single_mmap(struct vm_mmap *mmap);
void free_all_mmap(struct list *mmap_list);



#endif