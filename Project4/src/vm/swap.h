#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"
#define SECTORS_PER_PAGE 8
void swap_init(size_t size);
size_t swap_out(void *kaddr);
void swap_in(size_t used_index, void *kaddr);

#endif
