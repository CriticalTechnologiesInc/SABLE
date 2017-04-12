#include "mbi.h"
#include "elf.h"
#include "util.h"

int
__main(struct mbi *mbi, unsigned flags)
{
#ifndef NDEBUG
  out_string("Zeroing out SLB memory\n");
  wait(2000);
#endif
  memset((void *) 0x100000, 0, 0x10000);

  RESULT res = start_module(mbi);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });

  return 0;
}
