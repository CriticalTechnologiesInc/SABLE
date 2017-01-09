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
#include "keyboard.h"

const unsigned REALMODE_CODE = 0x20000;

/**
 * Function to output a hash.
 */
void show_hash(const char *s, TPM_DIGEST *hash) {
  out_string(s_message_label);
  out_string(s);
  for (UINT32 i = 0; i < 20; i++)
    out_hex(hash->digest[i], 7);
  out_char('\n');
}

TPM_AUTHDATA get_authdata(const char *str) {
  static const TPM_AUTHDATA zero_authdata = {{0}};
  int res;
  struct SHA1_Context ctx;

  out_string(str);
  res = get_string(STRING_BUF_SIZE, false);
  if (res > 0) {
    sha1_init(&ctx);
    sha1(&ctx, (BYTE *)string_buf, res);
    sha1_finish(&ctx);
    return *((TPM_AUTHDATA *) ctx.hash);
  } else {
    return zero_authdata;
  }
}

void configure(void) {
  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
  TPM_RESULT res;
  SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
  BYTE *sealedData = alloc(heap, 400, 0);
  BYTE *passPhrase = alloc(heap, STRING_BUF_SIZE, 0);
  memset(passPhrase, 0, STRING_BUF_SIZE);

  out_string(s_Please_enter_the_passphrase);
  UINT32 lenPassphrase = get_string(STRING_BUF_SIZE, true) + 1;
  memcpy(passPhrase, string_buf, lenPassphrase);

  TPM_AUTHDATA srkAuthData = get_authdata(s_enter_srkAuthData);
  TPM_AUTHDATA passPhraseAuthData = get_authdata(s_enter_passPhraseAuthData);
  TPM_AUTHDATA ownerAuthData = get_authdata(s_enter_ownerAuthData);

  memset((unsigned char *)sctx, 0, sizeof(SessionCtx));

  // select PCR 17 and 19
  sdTPM_PCR_SELECTION select = {ntohs(PCR_SELECT_SIZE), {0x0, 0x0, 0xa}};

  res = TPM_Start_OSAP(buffer, srkAuthData.authdata, TPM_ET_KEYHANDLE, TPM_KH_SRK, sctx);
  TPM_ERROR(res, s_TPM_Start_OSAP);

  out_string(s_Erasing_srk_authdata);
  memset(srkAuthData.authdata, 0, 20);

  out_string(s_Sealing_passPhrase);
  out_string((char *)passPhrase);
  res = TPM_Seal(buffer, select, passPhrase, lenPassphrase, sealedData, sctx,
                 passPhraseAuthData.authdata);
  TPM_ERROR(res, s_TPM_Seal);

  out_string(s_Erasing_passphrase_from_memory);
  memset(passPhrase, 0, lenPassphrase);

  out_string(s_Erasing_passphrase_authdata);
  memset(passPhraseAuthData.authdata, 0, 20);

  res = TPM_Start_OSAP(buffer, ownerAuthData.authdata, TPM_ET_OWNER, 0, sctx);
  TPM_ERROR(res, s_TPM_Start_OSAP);

  out_string(s_Erasing_owner_authdata);
  memset(ownerAuthData.authdata, 0, 20);

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
  dealloc(heap, passPhrase, 64);
}

void unsealPassphrase(void) {
  TPM_RESULT res;
  TPM_AUTHDATA srkAuthData = get_authdata(s_enter_srkAuthData);
  TPM_AUTHDATA passPhraseAuthData = get_authdata(s_enter_passPhraseAuthData);

  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
  SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);
  SessionCtx *sctxParent = alloc(heap, sizeof(SessionCtx), 0);
  SessionCtx *sctxEntity = alloc(heap, sizeof(SessionCtx), 0);

  BYTE *sealedData = alloc(heap, 400, 0);
  BYTE *unsealedData = alloc(heap, 100, 0);

  UINT32 *unsealedDataSize = alloc(heap, sizeof(UINT32), 0);
  memset(sctx, 0, sizeof(SessionCtx));

  memcpy(sctxParent->pubAuth.authdata, srkAuthData.authdata, 20);
  memcpy(sctxEntity->pubAuth.authdata, passPhraseAuthData.authdata, 20);

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
  get_string(3, true);

  if (bufcmp(s_YES, string_buf, 3))
    reboot();

  out_string(s_Erasing_passphrase_authdata);
  memset(passPhraseAuthData.authdata, 0, 20);

  out_string(s_Erasing_srk_authdata);
  memset(srkAuthData.authdata, 0, 20);

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
static int mbi_calc_hash(struct mbi *mbi, struct SHA1_Context *ctx) {
  TPM_EXTEND_RET res;
  TPM_DIGEST dig;

  CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, s_module_flag_missing);
  CHECK3(-12, !mbi->mods_count, s_no_module_to_hash);
  out_description(s_Hashing_modules_count, mbi->mods_count);

  struct module *m = (struct module *)(mbi->mods_addr);
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
  UINT32 heap_len = 0x00003000;
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
  struct SHA1_Context *ctx = alloc(heap, sizeof(struct SHA1_Context), 0);

  revert_skinit();

  ERROR(20, !mbi, s_no_mbi_in_sable);

  if (tis_init(TIS_BASE)) {
    ERROR(21, !tis_access(TIS_LOCALITY_2, 0), s_could_not_gain_TIS_ownership);
    ERROR(22, mbi_calc_hash(mbi, ctx), s_calc_hash_failed);

#ifndef NDEBUG
    TPM_RESULT res;
    TPM_DIGEST *dig = alloc(heap, sizeof(TPM_DIGEST), 0);

    res = TPM_PcrRead(ctx->buffer, dig, SLB_PCR_ORD);
    TPM_ERROR(res, s_TPM_PcrRead);
    show_hash(s_PCR17, dig);

    res = TPM_PcrRead(ctx->buffer, dig, MODULE_PCR_ORD);
    TPM_ERROR(res, s_TPM_PcrRead);
    show_hash(s_PCR19, dig);

    dealloc(heap, dig, sizeof(TPM_DIGEST));
    wait(1000);
#endif

    out_string("Configure now? [y/n]: ");
    get_string(1, true);
    if (!bufcmp("y", string_buf, 1)) {
      configure();
      ERROR(25, tis_deactivate_all(), s_tis_deactivate_failed);
      out_string(s_Configuration_complete_Rebooting_now);
      wait(5000);
      reboot();
    } else {
      unsealPassphrase();
    }

    ERROR(25, tis_deactivate_all(), s_tis_deactivate_failed);
  }

  // cleanup
  dealloc(heap, ctx, sizeof(struct SHA1_Context));

  ERROR(27, start_module(mbi), s_start_module_failed);
  return 28;
}
