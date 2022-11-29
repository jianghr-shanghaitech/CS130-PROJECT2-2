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
    struct file *file;            /* File to load */
    off_t offset;                 /* File offset */
    void *addr;                   /* User virtual address, key to he hash table */
    uint32_t read_bytes;          /* Bytes to read from file after offset */
    uint32_t zero_bytes;          /* Bytes to be zeroed, after read bytes */
    bool writable;                /* Whether the page is writable */
    size_t swap_id;               /* Index on swap bitmap returned by swap_out() */
    struct lock spte_lock;        /* Lock in case synchronization */
    int type;                     /* Type of this page */
    void* frame;                  /* Corresponding frame addr, NULL means not loaded frame */
    struct hash_elem hash_elem;   /* Hash table element */
};

void supp_page_table_init(struct hash *);
struct supp_page_table_entry *find_spte (struct hash *, uint8_t *);

bool page_lazy_load (struct file *, off_t, uint8_t *, uint32_t, uint32_t, bool, int);
bool page_load_file (struct supp_page_table_entry *);
bool page_swap_in (struct supp_page_table_entry *);

bool stack_grow (void *);

void free_supp_page_table (struct hash *);

#endif