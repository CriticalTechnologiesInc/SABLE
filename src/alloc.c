#ifndef ISABELLE
#include "tcg.h"
#include "exception.h"
#include "util.h"
#include "alloc.h"
#endif

#define KB 1024

struct mem_node {
  UINT32 size;           /* size of this data, in blocks */
  struct mem_node *next; /* where the next
                  mem_node is located, is NULL if there is no next node */
};
static struct mem_node *node = NULL;

#define BLOCK_SIZE 8 // must be at least sizeof(struct mem_node)
#define BITS_ALIGN 3 // must be log_2 of BLOCK_SIZE
#if (!(1 << BITS_ALIGN == BLOCK_SIZE))
#error "BITS_ALIGN is not log_2 of BLOCK_SIZE"
#endif

static struct mem_node heap[8 * KB / BLOCK_SIZE];

void init_heap(void) {
  ASSERT(!node);
  node = heap;
  *node =
      (struct mem_node){.size = (sizeof(heap) >> BITS_ALIGN) - 1, .next = NULL};
}

void *alloc(UINT32 size) {
  ASSERT(size > 0);
  UINT32 blocks =
      (size >> BITS_ALIGN) + 1; // FIXME: we might be overallocating here!
  if (node->size <= blocks)
    return NULL;

  struct mem_node *new_node = node + (blocks + 1);
  UINT32 prev_size = node->size;
  *node = (struct mem_node){.size = blocks, .next = new_node};
  *new_node = (struct mem_node){.size = prev_size - (blocks + 1), .next = NULL};
  void *ret = (void *)(node + 1);
  node = new_node;
  return ret;
}
