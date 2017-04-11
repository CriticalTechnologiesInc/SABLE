#ifndef ISABELLE
#include "tcg.h"
#include "exception.h"
#include "util.h"
#include "alloc.h"
#endif

struct mem_node {
  UINT32 size;           /* size of this data, in blocks */
  struct mem_node *next; /* where the next
                  mem_node is located, is NULL if there is no next node */
};

#define BLOCK_SIZE 8 // must be at least sizeof(struct mem_node)
#define BITS_ALIGN 3 // must be log_2 of BLOCK_SIZE
#if (!(1 << BITS_ALIGN == BLOCK_SIZE))
#error "BITS_ALIGN is not log_2 of BLOCK_SIZE"
#endif

void init_heap(void *heap, UINT32 heap_size) {
  ASSERT(((unsigned long)heap & 7) == 0);
  struct mem_node *n = heap;
  *n = (struct mem_node){.size = (heap_size >> BITS_ALIGN) - 1, .next = NULL};
}

void *alloc(void *heap, UINT32 size) {
  struct mem_node *n, *next_node = NULL;
  ASSERT(size > 0);
  UINT32 blocks =
      (size >> BITS_ALIGN) + 1; // FIXME: we might be overallocating here!

  for (n = heap; n && !next_node; n = n->next) {
    if (n->size < blocks) {
      next_node = n + (blocks + 1);
      *next_node =
          (struct mem_node){.size = n->size - (blocks + 1), .next = n->next};
    } else if (n->size == blocks) {
      next_node = n->next;
    }
  }
  if (!n)
    return NULL;

  *n = (struct mem_node){.size = blocks, .next = next_node};
  return (void *)(n + 1);
}
