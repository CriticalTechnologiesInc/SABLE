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
#include "keyboard.h"
#include "mp.h"
#include "sha.h"
#include "string.h"
#include "tpm.h"
#include "tpm_error.h"
#include "util.h"
#include "version.h"

#define REALMODE_CODE 0x20000

/* SABLE globals */

/* contains plaintext secrets */
static struct {
  TPM_AUTHDATA nv_auth;
  TPM_AUTHDATA pp_auth;
  TPM_AUTHDATA srk_auth;
  char passphrase[STRING_BUF_SIZE];
} secrets;

/* ciphertext passphrase */
static BYTE pp_blob[400];

/* selection of PCRs 17 and 19 */
static BYTE pcr_select_bytes[3] = {0x0, 0x0, 0xa};
static const TPM_PCR_SELECTION pcr_select = {
    .sizeOfSelect = sizeof(pcr_select_bytes), .pcrSelect = pcr_select_bytes};

/**
 * Function to output a hash.
 */
void show_hash(const char *s, TPM_DIGEST *hash) {
  out_string(s_message_label);
  out_string(s);
  for (UINT32 i = 0; i < 20; i++)
    out_hex(hash->bytes[i], 7);
  out_char('\n');
}

void get_authdata(const char *str /* in */, TPM_AUTHDATA *authdata /* out */) {
  static const TPM_AUTHDATA zero_authdata = {{0}};
  int res;

  out_string(str);
  res = get_string(STRING_BUF_SIZE, false);
  if (res > 0) {
    sha1_init();
    sha1((BYTE *)string_buf, res);
    *authdata = sha1_finish();
  } else {
    *authdata = zero_authdata;
  }
}

static void configure(void) {
  BYTE *buffer = alloc(heap, TCG_BUFFER_SIZE, 0);
  TPM_RESULT res;
  SessionCtx *sctx = alloc(heap, sizeof(SessionCtx), 0);

  out_string(s_Please_enter_the_passphrase);
  UINT32 lenPassphrase = get_string(sizeof(secrets.passphrase) - 1, true) + 1;
  memcpy(secrets.passphrase, string_buf, lenPassphrase);

  get_authdata(s_enter_srkAuthData, &secrets.srk_auth);
  get_authdata(s_enter_passPhraseAuthData, &secrets.pp_auth);
  get_authdata(s_enter_nvAuthData, &secrets.nv_auth);

  memset((unsigned char *)sctx, 0, sizeof(SessionCtx));

  res = TPM_Start_OSAP(buffer, secrets.srk_auth.bytes, TPM_ET_KEYHANDLE,
                       TPM_KH_SRK, sctx);
  TPM_ERROR(res, s_TPM_Start_OSAP);

  out_string(s_Sealing_passPhrase);
  out_string(secrets.passphrase);
  res = TPM_Seal(buffer, select, (BYTE *)secrets.passphrase, lenPassphrase,
                 pp_blob, sctx, secrets.pp_auth.bytes);
  TPM_ERROR(res, s_TPM_Seal);

  TPM_OIAP_RET oiap_ret = TPM_OIAP();
  TPM_ERROR(oiap_ret.returnCode, s_TPM_Start_OIAP);
  TPM_SESSION nv_session = oiap_ret.session;

  res = TPM_NV_WriteValueAuth(pp_blob, SEALED_DATA_SIZE, 0x04, 0,
                              secrets.nv_auth, nv_session);
  TPM_ERROR(res, s_TPM_NV_WriteValueAuth);

  // cleanup
  dealloc(heap, buffer, TCG_BUFFER_SIZE);
  dealloc(heap, sctx, sizeof(SessionCtx));
}

static void unsealPassphrase(void) {
  TPM_RESULT res;
  get_authdata(s_enter_srkAuthData, &secrets.srk_auth);
  get_authdata(s_enter_passPhraseAuthData, &secrets.pp_auth);

  res = TPM_NV_ReadValue(pp_blob, sizeof(pp_blob), 0x04, 0);
  TPM_ERROR(res, s_TPM_NV_ReadValueAuth);

  res = TPM_Start_OIAP(buffer, sctxParent);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_Start_OIAP(buffer, sctxEntity);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_Unseal(buffer, sealedData, unsealedData, STRING_BUF_SIZE,
  unsealedDataSize,
                   sctxParent, sctxEntity);
  TPM_WARNING(res, s_TPM_Unseal);

  out_string(s_Please_confirm_that_the_passphrase);
  out_string(s_Passphrase);
  out_string((char *)unsealedData);

  out_string(s_If_this_is_correct);
  get_string(3, true);

  if (bufcmp(s_YES, string_buf, 3))
    reboot();
}

/**
 *  Hash all multiboot modules.
 */
static int mbi_calc_hash(struct mbi *mbi) {
  TPM_EXTEND_RET res;
  TPM_DIGEST hash;

  CHECK3(-11, ~mbi->flags & MBI_FLAG_MODS, s_module_flag_missing);
  CHECK3(-12, !mbi->mods_count, s_no_module_to_hash);
  out_description(s_Hashing_modules_count, mbi->mods_count);

  struct module *m = (struct module *)(mbi->mods_addr);
  for (unsigned i = 0; i < mbi->mods_count; i++, m++) {
    sha1_init();

    CHECK3(-13, m->mod_end < m->mod_start, s_mod_end_less_than_start);

    sha1((BYTE *)m->mod_start, m->mod_end - m->mod_start);
    hash = sha1_finish();
    res = TPM_Extend(MODULE_PCR_ORD, hash);
    TPM_ERROR(res.returnCode, s_TPM_Extend);
  }

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

static int fixup(void) {
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

static int revert_skinit(void) {
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
  revert_skinit();

  ERROR(20, !mbi, s_no_mbi_in_sable);

  if (tis_init(TIS_BASE)) {
    ERROR(21, !tis_access(TIS_LOCALITY_2, 0), s_could_not_gain_TIS_ownership);
    ERROR(22, mbi_calc_hash(mbi), s_calc_hash_failed);

#ifndef NDEBUG
    TPM_PCRREAD_RET res;

    res = TPM_PCRRead(SLB_PCR_ORD);
    TPM_ERROR(res.returnCode, s_TPM_PcrRead);
    show_hash(s_PCR17, &res.outDigest);

    res = TPM_PCRRead(MODULE_PCR_ORD);
    TPM_ERROR(res.returnCode, s_TPM_PcrRead);
    show_hash(s_PCR19, &res.outDigest);

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

  // FIXME: take a closer look at how we could do this better
  memset(&secrets, 0, sizeof(secrets));

  ERROR(27, start_module(mbi), s_start_module_failed);
  return 28;
}
