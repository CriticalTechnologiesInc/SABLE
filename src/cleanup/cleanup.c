#include "mbi.h"
#include "elf.h"
#include "util.h"
#include "heap.h"
#include "alloc.h"

#define KB 1024
BYTE heap_array[8 * KB] __attribute__((aligned(8)));
BYTE *heap = heap_array;

int __main(struct mbi *mbi, unsigned flags) {
  init_heap(heap, sizeof(heap_array));
#ifndef NDEBUG
  out_string("Zeroing out SLB memory\n");
  wait(2000);
#endif
  memset((void *)0x100000, 0, 0x10000);

  RESULT res = start_module(mbi);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });

  return 0;
}
