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

#include "asm.h"
#include "dev.h"
#include "mbi.h"
#include "elf.h"
#include "macro.h"
#include "mp.h"
#include "platform.h"
#include "tcg.h"
#include "keyboard.h"
#include "sha.h"
#include "hmac.h"
#include "tis.h"
#include "tpm.h"
#include "tpm_error.h"
#include "tpm_ordinal.h"
#include "tpm_struct.h"
#include "util.h"
#include "version.h"

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

extern void configure(UINT32 index);
extern void trusted_boot(UINT32 index);

const char *const version_string =
    "SABLE:   v." SABLE_VERSION_MAJOR "." SABLE_VERSION_MINOR "\n";

TPM_AUTHDATA get_authdata(void) {
  static const TPM_AUTHDATA zero_authdata = {{0}};
  int res;
  SHA1_Context sctx;
  char auth_str[AUTHDATA_STR_SIZE];

  res = get_string(auth_str, AUTHDATA_STR_SIZE, false);
  if (res > 0) {
    sha1_init(&sctx);
    sha1(&sctx, (BYTE *)auth_str, res);
    sha1_finish(&sctx);
    return *(TPM_AUTHDATA *)&sctx.hash;
  } else {
    return zero_authdata;
  }
}

/* temporary solution, in the long term we should not rely on the TPM to
 * generate
 * nonces. */
TPM_NONCE get_nonce(void) {
  TPM_NONCE ret;
  TPM_RESULT res = TPM_GetRandom(ret.nonce, sizeof(TPM_NONCE));
  TPM_ERROR(res, "nonce generation failed");
  return ret;
}

/**
 *  Hash all multiboot modules.
 */
static int mbi_calc_hash(struct mbi *mbi) {
  SHA1_Context sctx;

  CHECK3(-11, ~mbi->flags & (enum mbi_enum)MBI_FLAG_MODS,
         "module flag missing");
  CHECK3(-12, !mbi->mods_count, "no module to hash");
  out_description("Hashing modules count:", mbi->mods_count);

  struct module *m = (struct module *)(mbi->mods_addr);
  for (unsigned i = 0; i < mbi->mods_count; i++, m++) {
    sha1_init(&sctx);

    CHECK3(-13, m->mod_end < m->mod_start, "mod_end less than start");

    sha1(&sctx, (BYTE *)m->mod_start, m->mod_end - m->mod_start);
    sha1_finish(&sctx);
    struct TPM_Extend_ret res = TPM_Extend(19, sctx.hash);
    TPM_ERROR(res.returnCode, TPM_Extend);
  }

  return 0;
}

/**
 * Prepare the TPM for skinit.
 * Returns a TIS_INIT_* value.
 */
static int prepare_tpm(void) {
  enum TIS_TPM_VENDOR vendor;
  TPM_RESULT res;

  vendor = tis_init();

  CHECK4(-60, 0 >= vendor, "tis init failed", vendor);
  CHECK3(-61, !tis_access(TIS_LOCALITY_0, 0), "could not gain TIS ownership");

  res = TPM_Startup(TPM_ST_CLEAR);
  if (res && res != TPM_E_INVALID_POSTINIT)
    TPM_ERROR(res, "TPM_Startup_Clear()");

  CHECK3(-62, tis_deactivate_all(), "tis deactivate failed");

  return res;
}

/**
 * This function runs before skinit and has to enable SVM in the processor
 * and disable all localities.
 */
int _main(struct mbi *m, unsigned flags) {

  out_string(version_string);
  ERROR(10, !m || flags != MBI_MAGIC2, "not loaded via multiboot");

  // set bootloader name
  m->flags |= (enum mbi_enum)MBI_FLAG_BOOT_LOADER_NAME;
  m->boot_loader_name = (unsigned)version_string;

  int revision = check_cpuid();
  if (0 >= prepare_tpm() || (0 > revision)) {
    if (0 > revision)
      out_info("No SVM platform");
    else
      out_info("Could not prepare the TPM");

    ERROR(11, start_module(m), "start module failed");
  }

  out_description("SVM revision:", revision);
  ERROR(12, enable_svm(), "Could not enable SVM");
  ERROR(13, stop_processors(),
        "sending an INIT IPI to other processors failed");

#ifndef NDEBUG
  out_info("call skinit");
  wait(1000);
#endif
  do_skinit();

  return 0;
}

/**
 * This code is executed after skinit.
 */
int sable(struct mbi *m) {
  revert_skinit();

  // TEMPORARY
  char *args = (char *) m->cmdline;
  args += 11;
  UINT32 counter = 0;
  UINT32 nvIndex = 0;

  while (args[counter] != '\0') {

    nvIndex *= 10;
    nvIndex += args[counter] - '0';
    counter++;
  }
  // TEMPORARY

  ERROR(20, !m, "no mbi in sable()");

  if (tis_init()) {
    ERROR(21, !tis_access(TIS_LOCALITY_2, 0), "could not gain TIS ownership");
    ERROR(22, mbi_calc_hash(m), "calc hash failed");

#ifndef NDEBUG
    struct TPM_PCRRead_ret pcr17 = TPM_PCRRead(17);
    TPM_ERROR(pcr17.returnCode, "TPM_PcrRead()");
    show_hash("PCR[17]: ", pcr17.outDigest);

    struct TPM_PCRRead_ret pcr19 = TPM_PCRRead(19);
    TPM_ERROR(pcr19.returnCode, "TPM_PcrRead()");
    show_hash("PCR[19]: ", pcr19.outDigest);

    wait(1000);
#endif

    char config_str[2];
    out_string("Configure now? [y/n]: ");
    get_string(config_str, sizeof(config_str) - 1, true);
    if (config_str[0] == 'y') {
      configure(nvIndex);
      ERROR(25, tis_deactivate_all(), "tis deactivate failed");
      out_string("\nConfiguration complete. Rebooting now...\n");
      wait(5000);
      reboot();
    } else {
      trusted_boot(nvIndex);
    }

    ERROR(25, tis_deactivate_all(), "tis deactivate failed");
  }

  ERROR(27, start_module(m), "start module failed");
  return 28;
}
