#ifndef SWAP_H
#define SWAP_H

#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct bitmap *swap_bitmap;
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init (void);
void swap_in (void *, int);
size_t swap_out (void *);

#endif