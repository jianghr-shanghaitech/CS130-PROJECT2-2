#ifndef SWAP_H
#define SWAP_H

#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct block* swap_block;
static struct bitmap *swap_bitmap;


void swap_init (void);
void swap_in (void *, int);
size_t swap_out (void *);

#endif