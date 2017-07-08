#ifndef ISABELLE
#include "tcg.h"
#include "exception.h"
#include "util.h"
#include "alloc.h"
#endif

struct mem_node {
  UINT32 size;           /* size of this data, in blocks, 
                            the most significant bit is the occupied (not free) flag */
  struct mem_node *next; /* where the next
                  mem_node is located, is NULL if there is no next node */
};
enum mem_node_consts{
  MEM_NODE_OCCUPIED_FLAG = 0x80000000
};

#define BLOCK_SIZE 8 // must be at least sizeof(struct mem_node)
#define BITS_ALIGN 3 // must be log_2 of BLOCK_SIZE
#if (!(1 << BITS_ALIGN == BLOCK_SIZE))
#error "BITS_ALIGN is not log_2 of BLOCK_SIZE"
#endif

void init_heap(void *heap, UINT32 heap_size) {
  ASSERT(((unsigned long)heap & 7) == 0);
  ASSERT((heap_size & MEM_NODE_OCCUPIED_FLAG) == 0);
  struct mem_node *n = heap;
  *n = (struct mem_node){.size = (heap_size >> BITS_ALIGN) - 1, .next = NULL};
}

void *alloc(void *heap, UINT32 size) {
  struct mem_node *n = heap, *next_node = NULL;
  ASSERT(size > 0);
  UINT32 blocks =
      (size >> BITS_ALIGN) + 1; // FIXME: we might be overallocating here!
  
  for (; n && ( (blocks > n->size & ~MEM_NODE_OCCUPIED_FLAG) || (n->size & MEM_NODE_OCCUPIED_FLAG)); n = n->next) {}
  if (!n)
    return NULL;

  UINT32 n_size = n->size & ~MEM_NODE_OCCUPIED_FLAG;

  if (blocks < n_size) {
    next_node = n + (blocks + 1);
    *next_node =
        (struct mem_node){.size = (n_size - (blocks + 1)) & ~MEM_NODE_OCCUPIED_FLAG, .next = n->next};
  } else {
    next_node = n->next;
  }

  *n = (struct mem_node){.size = blocks | MEM_NODE_OCCUPIED_FLAG, .next = next_node};
  return (void *)(n + 1);
}
