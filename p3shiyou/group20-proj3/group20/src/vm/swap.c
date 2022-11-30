#include "swap.h"

static struct lock swap_lock;

void
swap_init ()
{
    swap_bitmap = bitmap_create (block_size (block_get_role(BLOCK_SWAP)) / SECTORS_PER_PAGE);
    bitmap_set_all (swap_bitmap, false);
    lock_init (&swap_lock);
}

void 
swap_in (void *frame, int swap_index)
{
    lock_acquire (&swap_lock);
    size_t i = 0; 
    while (i < SECTORS_PER_PAGE)
    {
        block_read (block_get_role(BLOCK_SWAP), swap_index * SECTORS_PER_PAGE + i, frame + i * BLOCK_SECTOR_SIZE);
        i++;
    }
    bitmap_flip(swap_bitmap, swap_index);
    lock_release (&swap_lock);
}

size_t 
swap_out (void * frame)
{
    lock_acquire (&swap_lock);
    size_t swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    size_t i = 0;
    while (i < SECTORS_PER_PAGE)
    {
        block_write (block_get_role(BLOCK_SWAP), swap_index * SECTORS_PER_PAGE + i, frame + i * BLOCK_SECTOR_SIZE);
        i++;
    } 
    lock_release (&swap_lock);
    return swap_index;
}
