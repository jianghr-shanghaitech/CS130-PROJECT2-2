#include "swap.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct lock swap_lock;

void read_page_to_block(void*, int);
void write_page_to_block(void*, int);

void
swap_init ()
{
    swap_block = block_get_role(BLOCK_SWAP);
  
    swap_bitmap = bitmap_create (block_size (swap_block) / SECTORS_PER_PAGE);
  
    bitmap_set_all (swap_bitmap, false);
    lock_init (&swap_lock);
}

/* Load the page by swap_index and store in frame */
void 
swap_in (void *frame, int swap_index)
{
    lock_acquire (&swap_lock);
    read_page_to_block(frame, swap_index);
    bitmap_flip(swap_bitmap, swap_index);
    lock_release (&swap_lock);
}

/* Store frame into swap and return the index */
size_t 
swap_out (void * frame)
{
    lock_acquire (&swap_lock);
    size_t swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    write_page_to_block(frame, swap_index);
    lock_release (&swap_lock);
    return swap_index;
}

void 
read_page_to_block(void* frame, int index)
{
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_read (swap_block, index * SECTORS_PER_PAGE + i, frame + i * BLOCK_SECTOR_SIZE);
    }
}

void 
write_page_to_block(void* frame, int index)
{
    for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
        block_write (swap_block, index * SECTORS_PER_PAGE + i, frame + i * BLOCK_SECTOR_SIZE);
    }
}
