#ifndef ISABELLE
#include "alloc.h"
#include "asm.h"
#include "dev.h"
#include "hmac.h"
#include "keyboard.h"
#include "mp.h"
#include "tis.h"
#include "tpm.h"
#include "tpm_struct.h"
#include "util.h"
#include "version.h"
#endif
#ifdef __ARCH_AMD__
#include "amd.h"
#endif

BYTE * mgf1(BYTE *input, UINT32 inputLen, UINT32 outputLen) {

  UINT32 counter = 0;
  UINT32 outputLenRoundedUp;
  if (outputLen % 20 != 0) {
    outputLenRoundedUp = outputLen + (20 - (outputLen % 20));
  } else {
    outputLenRoundedUp = outputLen;
  }

  SHA1_Context sctx;
  TPM_DIGEST *output = alloc(outputLenRoundedUp);

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

