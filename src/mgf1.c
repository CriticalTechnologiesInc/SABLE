#ifndef ISABELLE
#include "alloc.h"
#include "heap.h"
#include "sha.h"
#include "asm.h"

BYTE *mgf1(BYTE *input, UINT32 inputLen, UINT32 outputLen) {

  UINT32 counter = 0;
  UINT32 outputLenRoundedUp;
  if (outputLen % 20 != 0) {
    outputLenRoundedUp = outputLen + (20 - (outputLen % 20));
  } else {
    outputLenRoundedUp = outputLen;
  }

  SHA1_Context sctx;
  TPM_DIGEST *output = alloc(heap, outputLenRoundedUp);

  while ((counter * 20) < outputLen) {

    int res = htonl(counter);
    sha1_init(&sctx);
    sha1(&sctx, (BYTE *)input, inputLen);
    sha1(&sctx, (BYTE *)&res, sizeof(res));
    sha1_finish(&sctx);
    output[counter] = sctx.hash;
    counter++;
  }

  return (BYTE *)output;
}
#endif
