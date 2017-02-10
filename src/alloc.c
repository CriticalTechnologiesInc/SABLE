/*
 * Copyright (C) 2014, National ICT Australia Limited. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * The name of National ICT Australia Limited nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "platform.h"
#include "alloc.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

/* Minimum granuality of the allocator (log2 of number of bytes). */
#define ALLOC_CHUNK_SIZE_BITS 3

/* Minimum alignment that the allocator will return. */
#define DEFAULT_ALIGNMENT_BITS 3

/* Disable "printk" error messages. */
#define printk(x...)

/*
 * Ensure condition "x" is true.
 */
#define assert(x)                                                              \
  do {                                                                         \
    if (!(x)) {                                                                \
      for (;;)                                                                 \
        ;                                                                      \
    }                                                                          \
  } while (0)

/* Is the given value aligned to the given alignment? */
#define IS_ALIGNED(x, val) (((x) % (1UL << val)) == 0UL)

/* Align "val" up to the next "2 ** align_bits" boundary. */
static UINT32 align_up(UINT32 val, UINT32 align_bits) {
  assert(align_bits < 32UL);
  return (val + ((1UL << align_bits) - 1UL)) & (~((1UL << align_bits) - 1UL));
}

/*
 * This simple allocator uses a linked list of "mem_nodes", each which
 * contain a size (indicating that the 'size' bytes from the beginning
 * of the mem_node are free, other than containing the mem_node itself),
 * and a pointer to the next. The list of "mem_nodes" are in sorted
 * order by their virtual address.
 *
 * We additionally have an initial "dummy" mem_node that begins the list
 * of size 0. This is to make the code simpler by each node having
 * a previous node. The typical method of dealing with this (taking
 * a pointer the previous node's next pointer) unfortunately does not
 * work due to limitations in the verification framework. (Pointers
 * can't be taken to a field of a struct.)
 *
 * To allocate, we find a mem_node which contains a valid range and
 * allocate the range out of the mem_node. This may completely use up
 * the mem_node (in which case, it is taken out of the list), be
 * allocated from the start or end of the mem_node (in which case it is
 * adjusted/moved), or be allocated from the middle of the mem_node (in
 * which case, we end up with one more mem_node than we begun with).
 *
 * Free'ing is the reverse process, ensuring that we correctly merge
 * mem_nodes as required.
 */

#define KB 1024
BYTE heap[8 * KB] = {0};

/*
 * Allocator memory node.
 *
 * Used as a node in a linked list tracking free memory regions.
 */
struct mem_node {
  UINT32 size;
  struct mem_node *next;
};
struct mem_node *prev = NULL;

/* Allocate a chunk of memory. */
void *alloc(UINT32 size) {
  assert(size > 0);
  if (!prev) {
    prev = (struct mem_node *)heap;
    prev->size = sizeof(heap) - sizeof(struct mem_node);
    prev->next = NULL;
  }

  if (prev->size < size)
    return NULL;

  /* Round size and alignment up to ALLOC_CHUNK_SIZE_BITS */
  size = align_up(size, ALLOC_CHUNK_SIZE_BITS);
  UINT32 total_size = size + sizeof(struct mem_node);

  struct mem_node *current = (struct mem_node *)(prev + total_size);
  current->size = prev->size - total_size;
  current->next = NULL;
  prev->size = size;
  prev->next = current;
  void *ret = (void *)(prev + 1);
  prev = current;
  return ret;
}
