/*
 * \brief   OSLO - Open Secure Loader
 * \date    2006-03-28
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */

#include "sable.h"
#include "alloc.h"
#include "dev.h"
#include "elf.h"
#include "mp.h"
#include "sha.h"
#include "string.h"
#include "tpm.h"
#include "tpm_error.h"
#include "util.h"
#include "version.h"

const unsigned REALMODE_CODE = 0x20000;
static char config = 0;

extern BYTE g_slb_zero;
#ifdef EXEC
BYTE g_end_of_low __attribute__((section(".slb.end_of_low"), aligned(4)));
BYTE g_aligned_end_of_low
    __attribute__((section(".slb.aligned_end_of_low"), aligned(4096)));
BYTE g_start_of_high __attribute__((section(".slb.start_of_high"), aligned(4)));
BYTE g_end_of_high __attribute__((section(".slb.end_of_high"), aligned(4)));
#endif

/**
 * Function to output a hash.
 */
static void show_hash(const char *s, TPM_DIGEST *hash) {
  out_string(s_message_label);
  out_string(s);
  for (UINT32 i = 0; i < 20; i++)
    out_hex(hash->digest[i], 7);
  out_char('\n');
}

void configure(BYTE *passPhrase, UINT32 lenPassphrase, BYTE *ownerAuthData,
               BYTE *srkAuthData, BYTE *passPhraseAuthData) {
  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
  TPM_RESULT res;
  SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
  BYTE *sealedData = alloc(heap, 400, 0);

  memset((unsigned char *)sctx, 0, sizeof(SessionCtx));

  // select PCR 17 and 19
  sdTPM_PCR_SELECTION select = {ntohs(PCR_SELECT_SIZE), {0x0, 0x0, 0xa}};

  res = TPM_Start_OSAP(buffer, srkAuthData, TPM_ET_KEYHANDLE, TPM_KH_SRK, sctx);
  TPM_ERROR(res, s_TPM_Start_OSAP);

  out_string(s_Erasing_srk_authdata);
  memset(srkAuthData, 0, 20);

  res = TPM_Seal(buffer, select, passPhrase, lenPassphrase, sealedData, sctx,
                 passPhraseAuthData);
  TPM_ERROR(res, s_TPM_Seal);

  out_string(s_Erasing_passphrase_from_memory);
  memset(passPhrase, 0, lenPassphrase);

  out_string(s_Erasing_passphrase_authdata);
  memset(passPhraseAuthData, 0, 20);

  res = TPM_Start_OSAP(buffer, ownerAuthData, TPM_ET_OWNER, 0, sctx);
  TPM_ERROR(res, s_TPM_Start_OSAP);

  out_string(s_Erasing_owner_authdata);
  memset(ownerAuthData, 0, 20);

  res = TPM_NV_DefineSpace(buffer, select, sctx);
  TPM_ERROR(res, s_TPM_NV_DefineSpace);

  res = TPM_Start_OIAP(buffer, sctx);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_NV_WriteValueAuth(buffer, sealedData, 400, sctx);
  TPM_ERROR(res, s_TPM_NV_WriteValueAuth);

  // cleanup
  dealloc(heap, buffer, TCG_BUFFER_SIZE);
  dealloc(heap, sctx, sizeof(SessionCtx));
  dealloc(heap, sealedData, 400);
}

void unsealPassphrase(BYTE *srkAuthData, BYTE *passPhraseAuthData) {
  TPM_RESULT res;

  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
  SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
  SessionCtx *sctxParent = alloc(heap, sizeof(SessionCtx), 0);
  SessionCtx *sctxEntity = alloc(heap, sizeof(SessionCtx), 0);
  char *entry = alloc(heap, 20 * sizeof(char), 0);

  BYTE *sealedData = alloc(heap, 400, 0);
  BYTE *unsealedData = alloc(heap, 100, 0);

  UINT32 *unsealedDataSize = alloc(heap, sizeof(UINT32), 0);
  memset(sctx, 0, sizeof(SessionCtx));

  memcpy(sctxParent->pubAuth.authdata, srkAuthData, 20);
  memcpy(sctxEntity->pubAuth.authdata, passPhraseAuthData, 20);

  res = TPM_Start_OIAP(buffer, sctx);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_NV_ReadValueAuth(buffer, sealedData, 400, sctx);
  TPM_ERROR(res, s_TPM_NV_ReadValueAuth);

  res = TPM_Start_OIAP(buffer, sctxParent);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_Start_OIAP(buffer, sctxEntity);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_Unseal(buffer, sealedData, unsealedData, 100, unsealedDataSize,
                   sctxParent, sctxEntity);
  TPM_WARNING(res, s_TPM_Unseal);

  out_string(s_Please_confirm_that_the_passphrase);
  out_string(s_Passphrase);
  out_string((char *)unsealedData);

  out_string(s_If_this_is_correct);
  const char *correctEntry = s_YES;
  unsigned int t = 0;
  char c;
  c = key_stroke_listener(); // for some reason, there's always an 'enter' char
  while (t < 20) {
    c = key_stroke_listener();
    if (c == 0x0D)
      break; // user hit 'return'
    if (c != 0) {
      out_char(c);
      entry[t] = c;
      t++;
    }
  }
  out_char('\n');

  if (bufcmp(correctEntry, entry, 3))
    reboot();

  out_string(s_Erasing_passphrase_authdata);
  memset(passPhraseAuthData, 0, 20);

  out_string(s_Erasing_srk_authdata);
  memset(srkAuthData, 0, 20);

  // cleanup
  dealloc(heap, buffer, TCG_BUFFER_SIZE);
  dealloc(heap, sctx, sizeof(SessionCtx));
  dealloc(heap, sctxParent, sizeof(SessionCtx));
  dealloc(heap, sctxEntity, sizeof(SessionCtx));

  dealloc(heap, sealedData, 400);
  dealloc(heap, unsealedData, 100);
  dealloc(heap, unsealedDataSize, sizeof(UINT32));
}

/**
 *  Hash all multiboot modules.
 */
static int mbi_calc_hash(struct mbi *mbi, BYTE *passPhrase,
                         UINT32 passPhraseBufSize, UINT32 *lenPassPhrase,
                         struct SHA1_Context *ctx) {
  TPM_EXTEND_RET res;
  TPM_DIGEST dig;

  CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, s_module_flag_missing);
  CHECK3(-12, !mbi->mods_count, s_no_module_to_hash);
  out_description(s_Hashing_modules_count, mbi->mods_count);

  struct module *m = (struct module *)(mbi->mods_addr);
  //
  // check for if this has the magic value in the first module
  // if it does, then skip the module, make mbi->mods_addr point to this new
  // module
  // set a flag that config file has been found
  if (!bufcmp((BYTE *)s_configmagic, (BYTE *)m->mod_start,
              strnlen_sable((BYTE *)s_configmagic, 20))) {
#ifndef NDEBUG
    out_info(s_config_magic_detected);
#endif
    config = 1;

    out_string(s_Please_enter_the_passphrase);

    UINT32 t = 0;
    char c = key_stroke_listener(); // for some reason, there's always an
                                    // 'enter' char
    while (t < passPhraseBufSize) {
      c = key_stroke_listener();
      if (c == 0x0D)
        break; // user hit 'return'
      if (c != 0) {
        out_char(c);
        passPhrase[t] = c;
        t++;
      }
    }
    *lenPassPhrase = t + 1;
    out_char('\n');

    // clear module for security reasons
    memset((BYTE *)m->mod_start, 0, m->mod_end - m->mod_start);

    // skip the module so it's invisible to future code
    m++;
    mbi->mods_addr = (unsigned)m;
    mbi->mods_count--;
  }

  for (unsigned i = 0; i < mbi->mods_count; i++, m++) {
    sha1_init(ctx);

    CHECK3(-13, m->mod_end < m->mod_start, s_mod_end_less_than_start);

#ifndef NDEBUG
    out_description(s_Module_starts_at, m->mod_start);
    out_description(s_Module_ends_at, m->mod_end);
#endif

    sha1(ctx, (BYTE *)m->mod_start, m->mod_end - m->mod_start);
    sha1_finish(ctx);
    memcpy(dig.digest, ctx->hash, sizeof(TPM_DIGEST));
    res = TPM_Extend(MODULE_PCR_ORD, dig);
    TPM_ERROR(res.returnCode, s_TPM_Extend);
  }

  wait(10000);

  return 0;
}

/**
 * Prepare the TPM for skinit.
 * Returns a TIS_INIT_* value.
 */
static int prepare_tpm(BYTE *buffer) {
  int tpm;
  TPM_RESULT res;

  tpm = tis_init(TIS_BASE);

  CHECK4(-60, 0 >= tpm, s_tis_init_failed, tpm);
  CHECK3(-61, !tis_access(TIS_LOCALITY_0, 0), s_could_not_gain_tis_ownership);

  res = TPM_Startup_Clear(buffer);
  if (res && res != TPM_E_INVALID_POSTINIT)
    TPM_ERROR(res, s_TPM_Startup_Clear);

  CHECK3(-62, tis_deactivate_all(), s_tis_deactivate_failed);

  return tpm;
}

/**
 * This function runs before skinit and has to enable SVM in the processor
 * and disable all localities.
 */
int _main(struct mbi *mbi, unsigned flags) {
  // initialize the heap
  UINT32 heap_len = 0x00040000;
  init_allocator();
  add_mem_pool(heap, heap->head + sizeof(struct mem_node), heap_len);

  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);

  out_string(s_version_string);
  ERROR(10, !mbi || flags != MBI_MAGIC2, s_not_loaded_via_multiboot);

  // set bootloader name
  mbi->flags |= MBI_FLAG_BOOT_LOADER_NAME;
  mbi->boot_loader_name = (unsigned)s_version_string;

  int revision = check_cpuid();
  if (0 >= prepare_tpm(buffer) || (0 > revision)) {
    if (0 > revision)
      out_info(s_No_SVM_platform);
    else
      out_info(s_Could_not_prepare_TPM);

    ERROR(11, start_module(mbi), s_start_module_failed);
  }

  out_description(s_SVM_revision, revision);
  ERROR(12, enable_svm(), s_SVM_revision);
  ERROR(13, stop_processors(), s_sending_an_INIT_IPI);

  // cleanup
  dealloc(heap, buffer, TCG_BUFFER_SIZE);

#ifndef NDEBUG
  out_info(s_call_skinit);
  wait(1000);
#endif
  do_skinit();

  return 0;
}

/* Note: This function Assumes a 4KB stack.  A more elegant solution
 * would probably define some symbols and let the linker script
 * determine the stack size.
 */
/*
void zero_stack (void) __attribute__ ((section (".text.slb")));
void zero_stack (void)
{
    unsigned int esp;
    unsigned int stack_base;
    unsigned int ptr;

    __asm__ __volatile__("movl %%esp, %0 " : "=m" (esp) );

    stack_base = (0xFFFFFFFF << 12) & esp;  // 2^12 = 4k

    if (stack_base <= 0) {
        // TODO: throw error!!!
      return;
    }

    // Zero out the stack 4 bytes at a time
    for (ptr = stack_base; ptr < esp; ptr+=4) {
      *((long*) ptr) = 0;
    }

    // Make sure we get the 0-3 bytes that may remain unzeroed
    for (ptr = ptr - 4; ptr < esp; ptr++) {
      *((char*) ptr) = 0;
    }
}
*/

int fixup(void) {
  unsigned i;
  out_info(s_patch_CPU_name_tag);
  CHECK3(-10, strnlen_sable((BYTE *)s_CPU_NAME, 1024) >= 48,
         s_cpu_name_to_long);

  for (i = 0; i < 6; i++)
    wrmsr(0xc0010030 + i, *(unsigned long long *)(s_CPU_NAME + i * 8));

  out_info(s_halt_APs_in_init_state);
  int revision;
  /**
   * Start the stopped APs and execute some fixup code.
   */
  memcpy((char *)REALMODE_CODE, &smp_init_start,
         &smp_init_end - &smp_init_start);
  CHECK3(-2, start_processors(REALMODE_CODE), s_sending_an_STARTUP_IPI);
  revision = enable_svm();
  CHECK3(12, revision, s_could_not_enable_SVM);
  out_description(s_SVM_revision, revision);
  out_info(s_enable_global_interrupt_flag);

#ifdef EXEC
  asm volatile("stgi"); // Not included in proof!
#endif

  return 0;
}

int revert_skinit(void) {
  if (0 < check_cpuid()) {
    if (disable_dev_protection())
      out_info(s_DEV_disable_failed);

    CHECK3(11, fixup(), s_fixup_failed);
    out_info(s_fixup_done);
  }

  ERROR(12, pci_iterate_devices(), s_could_not_iterate_over_the_devices);

  return 0;
}

/**
 * This code is executed after skinit.
 */
/* int sable(struct mbi *mbi) __attribute__ ((section (".text.slb"))); */
int sable(struct mbi *mbi) {
  TPM_RESULT res;
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct SHA1_Context *ctxSrk = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct SHA1_Context *ctxOwn = alloc(heap, sizeof(struct SHA1_Context), 0);
  struct SHA1_Context *ctxPas = alloc(heap, sizeof(struct SHA1_Context), 0);
  TPM_DIGEST *dig = alloc(heap, sizeof(TPM_DIGEST), 0);
  BYTE *ownerAuthData = alloc(heap, 20, 0);
  BYTE *srkAuthData = alloc(heap, 20, 0);
  BYTE *passPhraseAuthData = alloc(heap, 20, 0);
  BYTE *passPhrase = alloc(heap, 64, 0);
  UINT32 *lenPassphrase = alloc(heap, sizeof(UINT32), 0);
  UINT32 ownerAuthLen;
  UINT32 srkAuthLen;
  UINT32 passAuthLen;

  revert_skinit();

  memset(passPhrase, 0, 64);
  *lenPassphrase = 0;
  memset(ownerAuthData, 0, 20);
  ownerAuthLen = 0;
  memset(srkAuthData, 0, 20);
  srkAuthLen = 0;
  memset(passPhraseAuthData, 0, 20);
  passAuthLen = 0;

  ERROR(20, !mbi, s_no_mbi_in_sable);
  out_string(s_enter_srkAuthData);
  srkAuthLen = keyboardReader(srkAuthData, 20);

  if (srkAuthLen > 0) {
    sha1_init(ctxSrk);
    sha1(ctxSrk, srkAuthData, srkAuthLen);
    sha1_finish(ctxSrk);
  } else {
    memset(ctxSrk->hash, 0, 20);
  }

  out_string(s_enter_passPhraseAuthData);

  passAuthLen = keyboardReader(passPhraseAuthData, 20);

  if (passAuthLen > 0) {
    sha1_init(ctxPas);
    sha1(ctxPas, passPhraseAuthData, passAuthLen);
    sha1_finish(ctxPas);
  } else {
    memset(ctxPas->hash, 0, 20);
  }

  if (tis_init(TIS_BASE)) {
    ERROR(21, !tis_access(TIS_LOCALITY_2, 0), s_could_not_gain_TIS_ownership);

    res = TPM_PcrRead(ctx->buffer, dig, SLB_PCR_ORD);
    TPM_ERROR(res, s_TPM_PcrRead);

#ifndef NDEBUG
    show_hash(s_PCR17, dig);
    wait(1000);
#endif

    ERROR(22, mbi_calc_hash(mbi, passPhrase, 64, lenPassphrase, ctx),
          s_calc_hash_failed);

#ifndef NDEBUG
    show_hash(s_PCR19, dig);
    dump_pcrs(ctx->buffer);
#endif

    if (config == 1) {
      out_string(s_Sealing_passPhrase);
      out_string((char *)passPhrase);
      out_string(s_to_PCR19_with_value);
      show_hash(s_PCR19, dig);
      wait(1000);

      out_string(s_enter_ownerAuthData);

      ownerAuthLen = keyboardReader(ownerAuthData, 20);

      if (ownerAuthLen > 0) {
        sha1_init(ctxOwn);
        sha1(ctxOwn, ownerAuthData, ownerAuthLen);
        sha1_finish(ctxOwn);
      } else {
        memset(ctxOwn->hash, 0, 20);
      }

      configure(passPhrase, *lenPassphrase, ctxOwn->hash, ctxSrk->hash,
                ctxPas->hash);
      ERROR(25, tis_deactivate_all(), s_tis_deactivate_failed);
      out_string(s_Configuration_complete_Rebooting_now);
      wait(5000);
      reboot();
    } else {
      unsealPassphrase(ctxSrk->hash, ctxPas->hash);
    }

    ERROR(25, tis_deactivate_all(), s_tis_deactivate_failed);
  }

  memset(srkAuthData, 0, 20);
  memset(ownerAuthData, 0, 20);
  memset(passPhraseAuthData, 0, 20);

  // zero_stack();

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));
  dealloc(heap, ctxSrk, sizeof(struct SHA1_Context));
  dealloc(heap, ctxOwn, sizeof(struct SHA1_Context));
  dealloc(heap, ctxPas, sizeof(struct SHA1_Context));
  dealloc(heap, dig, sizeof(TPM_DIGEST));
  dealloc(heap, passPhrase, 64);
  dealloc(heap, lenPassphrase, sizeof(UINT32));
  dealloc(heap, srkAuthData, 20);
  dealloc(heap, ownerAuthData, 20);
  dealloc(heap, passPhraseAuthData, 20);

  ERROR(27, start_module(mbi), s_start_module_failed);
  return 28;
}