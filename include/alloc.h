#ifndef __ALLOC_H__
#define __ALLOC_H__

#include "platform.h"

void init_heap(void *heap, UINT32 heap_size);
void *alloc(void *heap, UINT32 size);

#endif
