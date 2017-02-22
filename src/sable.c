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
#include "platform.h"
#include "exception.h"
#include "dev.h"
#include "mbi.h"
#include "elf.h"
#include "macro.h"
#include "mp.h"
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

// Result generators
RESULT_GEN(TPM_NONCE);
RESULT_GEN(TPM_AUTHDATA);

extern void configure(void);
extern void trusted_boot(void);

const char *const version_string =
    "SABLE:   v." SABLE_VERSION_MAJOR "." SABLE_VERSION_MINOR "\n";

/* EXCEPT:
 * ERROR_SHA1_DATA_SIZE
 */
RESULT(TPM_AUTHDATA) get_authdata(void) {
  RESULT(TPM_AUTHDATA) ret = {.exception.error = NONE};
  static const TPM_AUTHDATA zero_authdata = {{0}};
  int res;
  SHA1_Context sctx;
  char auth_str[AUTHDATA_STR_SIZE];

  res = get_string(auth_str, AUTHDATA_STR_SIZE, false);
  if (res > 0) {
    sha1_init(&sctx);
    RESULT sha1_ret = sha1(&sctx, (BYTE *)auth_str, res);
    THROW(sha1_ret.exception);
    sha1_finish(&sctx);
    ret.value = *(TPM_AUTHDATA *)&sctx.hash;
  } else {
    ret.value = zero_authdata;
  }

  return ret;
}

/* Except:
 * ERROR_TPM
 * ERROR_TPM_BAD_OUTPUT_PARAM
 * temporary solution, in the long term we should not rely on the TPM to
 * generate nonces. */
RESULT(TPM_NONCE) get_nonce(void) {
  RESULT(TPM_NONCE) ret = {.exception.error = NONE};
  RESULT get_random_res;
  get_random_res = TPM_GetRandom(ret.value.nonce, sizeof(TPM_NONCE));
  THROW(get_random_res.exception);
  return ret;
}

/* EXCEPT:
 * ERROR_BAD_MODULE
 * ERROR_NO_MODULE
 * ERROR_TPM
 * ERROR_TPM_BAD_OUTPUT_PARAM
 *
 * Hash all multiboot modules.
 */
static RESULT mbi_calc_hash(struct mbi *mbi) {
  RESULT ret = {.exception.error = NONE};
  RESULT(TPM_PCRVALUE) extend_ret;
  RESULT sha1_ret;
  SHA1_Context sctx;

  ERROR(~mbi->flags & (enum mbi_enum)MBI_FLAG_MODS, ERROR_BAD_MODULE,
        "module flag missing");
  ERROR(!mbi->mods_count, ERROR_NO_MODULE, "no module to hash");
  out_description("Hashing modules count:", mbi->mods_count);

  struct module *m = (struct module *)(mbi->mods_addr);
  for (unsigned i = 0; i < mbi->mods_count; i++, m++) {
    sha1_init(&sctx);

    ERROR(m->mod_end < m->mod_start, ERROR_BAD_MODULE,
          "mod_end less than start");
    sha1_ret = sha1(&sctx, (BYTE *)m->mod_start, m->mod_end - m->mod_start);
    THROW(sha1_ret.exception);
    sha1_finish(&sctx);

    extend_ret = TPM_Extend(19, sctx.hash);
    THROW(extend_ret.exception);
  }

  return ret;
}

/* EXCEPT:
 * ERROR_TPM
 * ERROR_TPM_BAD_OUTPUT_PARAM
 *
 * Prepare the TPM for skinit.
 * Returns a TIS_INIT_* value.
 */
static RESULT prepare_tpm(void) {
  RESULT ret = {.exception.error = NONE};
  RESULT tpm_ret;
  enum TIS_TPM_VENDOR vendor;

  vendor = tis_init();

  ERROR(0 >= vendor, ERROR_BAD_TPM_VENDOR, "tis init failed");
  RESULT tis_access_ret = tis_access(TIS_LOCALITY_0, 0);
  THROW(tis_access_ret.exception);

  RESULT tpm_startup_ret = TPM_Startup(TPM_ST_CLEAR);
  CATCH(tpm_startup_ret.exception, ERROR_TPM | TPM_E_INVALID_POSTINIT,
        out_string("TPM already initialized\n"));
  THROW(tpm_ret.exception);

  RESULT tis_deactivate_res = tis_deactivate_all();
  THROW(tis_deactivate_res.exception);

  return ret;
}

/**
 * This function runs before skinit and has to enable SVM in the processor
 * and disable all localities.
 */
RESULT pre_skinit(struct mbi *m, unsigned flags) {
  RESULT ret = {.exception.error = NONE};
  out_string(version_string);

  ERROR(!m, ERROR_NO_MBI, "not loaded via multiboot");
  ERROR(flags != MBI_MAGIC2, ERROR_BAD_MBI, "not loaded via multiboot");

  // set bootloader name
  m->flags |= (enum mbi_enum)MBI_FLAG_BOOT_LOADER_NAME;
  m->boot_loader_name = (unsigned)version_string;

  RESULT tpm = prepare_tpm();
  THROW(tpm.exception);

  RESULT(UINT32) cpuid = check_cpuid();
  THROW(cpuid.exception);
  out_description("SVM revision:", cpuid.value);

  RESULT svm = enable_svm();
  THROW(svm.exception);
  RESULT sp = stop_processors();
  THROW(sp.exception);

#ifndef NDEBUG
  out_info("call skinit");
  wait(1000);
#endif
  do_skinit();

  return ret;
}

void _pre_skinit(struct mbi *m, unsigned flags) {
  RESULT res = pre_skinit(m, flags);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });
}

/**
 * This code is executed after skinit.
 */
RESULT post_skinit(struct mbi *m) {
  RESULT ret = {.exception.error = NONE};

  RESULT revert_skinit_ret = revert_skinit();
  THROW(revert_skinit_ret.exception);

  ERROR(20, !m, "no mbi in sable()");

  if (tis_init()) {
    RESULT tis_access_ret = tis_access(TIS_LOCALITY_2, 0);
    THROW(tis_access_ret.exception);
    RESULT mbi_calc_hash_ret = mbi_calc_hash(m);
    THROW(mbi_calc_hash_ret.exception);

#ifndef NDEBUG
    RESULT(TPM_PCRVALUE) pcr17 = TPM_PCRRead(17);
    THROW(pcr17.exception);
    show_hash("PCR[17]: ", pcr17.value);

    RESULT(TPM_PCRVALUE) pcr19 = TPM_PCRRead(19);
    THROW(pcr19.exception);
    show_hash("PCR[19]: ", pcr19.value);

    wait(1000);
#endif

    char config_str[2];
    out_string("Configure now? [y/n]: ");
    get_string(config_str, sizeof(config_str) - 1, true);
    if (config_str[0] == 'y') {
      configure();
      RESULT tis_deactiv = tis_deactivate_all();
      THROW(tis_deactiv.exception);
      out_string("\nConfiguration complete. Rebooting now...\n");
      wait(5000);
      reboot();
    } else {
      trusted_boot();
      RESULT tis_deactiv = tis_deactivate_all();
      THROW(tis_deactiv.exception);
    }
  }

  RESULT start_module_ret = start_module(m);
  THROW(start_module_ret.exception);

  return ret;
}

void _post_skinit(struct mbi *m) {
  RESULT res = post_skinit(m);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });
}
