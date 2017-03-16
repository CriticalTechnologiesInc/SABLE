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

#ifndef ISABELLE
#include "tcg.h"
#include "exception.h"
#include "util.h"
#include "alloc.h"
#endif

#define KB 1024

struct mem_node {
  UINT16 size; /* size of this data, in blocks */
  UINT16 next; /* offset into the heap (in blocks) where the next
                  mem_node is located, is 0 if there is no next node */
};
static struct mem_node *node = NULL;

#define BLOCK_SIZE 4 // must be at least sizeof(struct mem_node)
#define BITS_ALIGN 2 // must be log_2 of BLOCK_SIZE
#if (!(1 << BITS_ALIGN == BLOCK_SIZE))
#error "BITS_ALIGN is not log_2 of BLOCK_SIZE
#endif

static struct mem_node heap[8 * KB / BLOCK_SIZE];

void init_heap(void) {
  ASSERT(!node);
  node = heap;
  *node =
      (struct mem_node){.size = (sizeof(heap) >> BITS_ALIGN) - 1, .next = 0};
}

void *alloc(UINT16 size) {
  ASSERT(size > 0);
  UINT16 blocks = (size >> BITS_ALIGN) + 1; // FIXME: we might be overallocating here!
  if (node->size <= blocks)
    return NULL;

  struct mem_node *new_node = (struct mem_node *)(node + (blocks + 1));
  UINT16 prev_size = node->size;
  *node = (struct mem_node){.size = blocks, .next = new_node - heap};
  *new_node = (struct mem_node){.size = prev_size - (blocks + 1), .next = 0};
  void *ret = (void *)(node + 1);
  node = new_node;
  return ret;
}

int test_func(int y) {
  int *x = alloc(sizeof(int));
  *x = y;
  return *x;
}
