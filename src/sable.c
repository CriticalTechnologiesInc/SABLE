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

#ifndef ISABELLE
#include "alloc.h"
#include "asm.h"
#include "dev.h"
#include "elf.h"
#include "hmac.h"
#include "keyboard.h"
#include "mbi.h"
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

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

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

// Result generators
RESULT_GEN(TPM_NONCE);
RESULT_GEN(TPM_AUTHDATA);

#ifndef ISABELLE
const char *const version_string =
    "SABLE:   v." SABLE_VERSION_MAJOR "." SABLE_VERSION_MINOR "\n";

/* EXCEPT:
 * ERROR_SHA1_DATA_SIZE
 */
RESULT_(TPM_AUTHDATA) get_authdata(void) {
  RESULT_(TPM_AUTHDATA) ret = {.exception.error = NONE};
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
RESULT_(TPM_NONCE) get_nonce(void) {
  RESULT_(TPM_NONCE) ret = {.exception.error = NONE};
  RESULT get_random_res;
  get_random_res = TPM_GetRandom(ret.value.nonce, sizeof(TPM_NONCE));
  THROW(get_random_res.exception);
  return ret;
}
#endif

RESULT_(TPM_AUTHDATA) get_authdata(void);
RESULT_(TPM_NONCE) get_nonce(void);

static TPM_SESSION *sessions[2] = {NULL, NULL};

RESULT_GEN(TPM_PCR_INFO_LONG);

// Construct pcr_info, which contains the TPM state conditions under which
// the passphrase may be sealed/unsealed
static RESULT_(TPM_PCR_INFO_LONG) get_pcr_info(void) {
  RESULT_(TPM_PCR_INFO_LONG) ret = {.exception.error = NONE};
  TPM_PCRVALUE *pcr_values = alloc(2 * sizeof(TPM_PCRVALUE));
  BYTE *pcr_select_bytes = alloc(3);
  pcr_select_bytes[0] = 0x00;
  pcr_select_bytes[1] = 0x00;
  pcr_select_bytes[2] = 0x0a;
  TPM_PCR_SELECTION pcr_select = {.sizeOfSelect = 3,
                                  .pcrSelect = (BYTE *)pcr_select_bytes};
  RESULT_(TPM_PCRVALUE) pcr17 = TPM_PCRRead(17);
  THROW(pcr17.exception);
  pcr_values[0] = pcr17.value;
  RESULT_(TPM_PCRVALUE) pcr19 = TPM_PCRRead(19);
  THROW(pcr19.exception);
  pcr_values[1] = pcr19.value;
  TPM_PCR_COMPOSITE composite = {.select = pcr_select,
                                 .valueSize = 2 * sizeof(TPM_PCRVALUE),
                                 .pcrValue = (TPM_PCRVALUE *)pcr_values};
  TPM_COMPOSITE_HASH composite_hash = get_TPM_COMPOSITE_HASH(composite);
  ret.value.tag = TPM_TAG_PCR_INFO_LONG;
  ret.value.localityAtCreation = TPM_LOC_TWO;
  ret.value.localityAtRelease = TPM_LOC_TWO;
  ret.value.creationPCRSelection = pcr_select;
  ret.value.releasePCRSelection = pcr_select;
  ret.value.digestAtCreation = composite_hash;
  ret.value.digestAtRelease = composite_hash;
  return ret;
}

static RESULT_(TPM_STORED_DATA12)
    seal_passphrase(TPM_AUTHDATA srk_auth, TPM_AUTHDATA pp_auth,
                    const char *passphrase, UINT32 lenPassphrase) {
  RESULT_(TPM_STORED_DATA12) ret = {.exception.error = NONE};

  // Initialize an OSAP session for the SRK
  RESULT_(TPM_NONCE) nonceOddOSAP = get_nonce();
  THROW(nonceOddOSAP.exception);
  RESULT osap_ret =
      TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, nonceOddOSAP.value, &sessions[0]);
  THROW(osap_ret.exception);

  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  // Generate the shared secret (for SRK authorization)
  TPM_SECRET sharedSecret =
      sharedSecret_gen(srk_auth, sessions[0]->osap->nonceEvenOSAP,
                       sessions[0]->osap->nonceOddOSAP);

  // Encrypt the new passphrase authdata
  TPM_ENCAUTH encAuth =
      encAuth_gen(pp_auth, sharedSecret, sessions[0]->nonceEven);

  RESULT_(TPM_PCR_INFO_LONG) pcr_info = get_pcr_info();
  THROW(pcr_info.exception);

  UINT32 seedLen =
      sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3 + sizeof(TPM_SECRET);
  BYTE *seed = alloc(seedLen);
  memcpy(seed, &sessions[0]->nonceEven, sizeof(TPM_NONCE));
  memcpy(seed + sizeof(TPM_NONCE), &sessions[0]->nonceOdd, sizeof(TPM_NONCE));
  memcpy(seed + sizeof(TPM_NONCE) + sizeof(TPM_NONCE), "XOR", 3);
  memcpy(seed + sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3, &sharedSecret,
         sizeof(TPM_SECRET));
  const BYTE *mask = mgf1(seed, seedLen, lenPassphrase);
  BYTE *passEnc = alloc(lenPassphrase);
  do_xor((const BYTE *)passphrase, mask, passEnc, lenPassphrase);

  // Encrypt the passphrase using the SRK
  return TPM_Sealx(TPM_KH_SRK, encAuth, pcr_info.value, passEnc, lenPassphrase,
                   &sessions[0], sharedSecret);
}

static RESULT write_passphrase(TPM_AUTHDATA nv_auth,
                               TPM_STORED_DATA12 sealedData, UINT32 index) {
  RESULT ret = {.exception.error = NONE};

  RESULT oiap_ret = TPM_OIAP(&sessions[0]);
  THROW(oiap_ret.exception);
  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  struct extracted_TPM_STORED_DATA12 x = extract_TPM_STORED_DATA12(sealedData);
  return TPM_NV_WriteValueAuth(x.data, x.dataSize, index, 0, nv_auth,
                               &sessions[0]);
}

RESULT configure(UINT32 index) {
  RESULT ret = {.exception.error = NONE};
  char *passphrase = alloc(PASSPHRASE_STR_SIZE);

  // get the passphrase, passphrase authdata, and SRK authdata
  EXCLUDE(out_string("Please enter the passphrase (" xstr(
      PASSPHRASE_STR_SIZE) " char max): ");)
  UINT32 lenPassphrase =
      get_string(passphrase, PASSPHRASE_STR_SIZE - 1, true) + 1;
  EXCLUDE(out_string("Please enter the passPhraseAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) pp_auth = get_authdata();
  THROW(pp_auth.exception);
  EXCLUDE(out_string("Please enter the srkAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) srk_auth = get_authdata();
  THROW(srk_auth.exception);

  // seal the passphrase to the pp_blob buffer
  RESULT_(TPM_STORED_DATA12)
  sealedData =
      seal_passphrase(srk_auth.value, pp_auth.value, passphrase, lenPassphrase);
  THROW(sealedData.exception);

  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) nv_auth = get_authdata();
  THROW(nv_auth.exception);

  // write the sealed passphrase to disk
  return write_passphrase(nv_auth.value, sealedData.value, index);
}

static RESULT_(TPM_STORED_DATA12) read_passphrase(UINT32 index) {
#ifdef NV_OWNER_REQUIRED
  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) nv_auth_ret = get_authdata();
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), nv_auth_ret.exception);

  const OPTION(TPM_AUTHDATA)
      nv_auth = {.value = nv_auth_ret.value, .hasValue = true};

  RESULT owner_oiap_ret = TPM_OIAP(&sessions[0]);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), owner_oiap_ret.exception);
  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  RESULT_(HEAP_DATA)
  val = TPM_NV_ReadValue(index, 0, 400, nv_auth, &sessions[0]);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), val.exception);
#else
  const OPTION(TPM_AUTHDATA) nv_auth = {.hasValue = false};

  RESULT_(HEAP_DATA) val = TPM_NV_ReadValue(index, 0, 400, nv_auth, NULL);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), val.exception);
#endif
  return (RESULT_(TPM_STORED_DATA12)){
      .exception.error = NONE,
      .value = unpack_TPM_STORED_DATA12(val.value.data, val.value.dataSize)};
}

typedef const char *CSTRING;
RESULT_GEN(CSTRING);

static RESULT_(CSTRING)
    unseal_passphrase(TPM_AUTHDATA srk_auth, TPM_AUTHDATA pp_auth,
                      TPM_STORED_DATA12 sealed_pp) {
  RESULT_(CSTRING) ret = {.exception.error = NONE};

  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  RESULT srk_osap_ret =
      TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, nonceOdd.value, &sessions[0]);
  THROW(srk_osap_ret.exception);
  sessions[0]->continueAuthSession = FALSE;
  TPM_SECRET sharedSecret =
      sharedSecret_gen(srk_auth, sessions[0]->osap->nonceEvenOSAP,
                       sessions[0]->osap->nonceOddOSAP);

  RESULT pp_oiap_ret = TPM_OIAP(&sessions[1]);
  THROW(pp_oiap_ret.exception);
  nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[1]->nonceOdd = nonceOdd.value;
  sessions[1]->continueAuthSession = FALSE;

  UINT32 seedLen =
      sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3 + sizeof(TPM_SECRET);
  BYTE *seed = alloc(seedLen);
  memcpy(seed, &sessions[0]->nonceEven, sizeof(TPM_NONCE));
  memcpy(seed + sizeof(TPM_NONCE), &sessions[0]->nonceOdd, sizeof(TPM_NONCE));
  memcpy(seed + sizeof(TPM_NONCE) + sizeof(TPM_NONCE), "XOR", 3);
  memcpy(seed + sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3, &sharedSecret,
         sizeof(TPM_SECRET));

  RESULT_(HEAP_DATA)
  unseal_ret = TPM_Unseal(sealed_pp, TPM_KH_SRK, sharedSecret, &sessions[0],
                          pp_auth, &sessions[1]);
  THROW(unseal_ret.exception);

  const BYTE *mask = mgf1(seed, seedLen, unseal_ret.value.dataSize);
  BYTE *passUnc = alloc(unseal_ret.value.dataSize);
  do_xor(unseal_ret.value.data, mask, passUnc, unseal_ret.value.dataSize);

  ret.value = (CSTRING)passUnc;

  return ret;
}

RESULT trusted_boot(UINT32 index) {
  RESULT ret = {.exception.error = NONE};
  RESULT_(TPM_STORED_DATA12) sealed_pp = read_passphrase(index);
  THROW(sealed_pp.exception);

  EXCLUDE(out_string("Please enter the passPhraseAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) pp_auth = get_authdata();
  THROW(pp_auth.exception);
  EXCLUDE(out_string("Please enter the srkAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) srk_auth = get_authdata();
  THROW(srk_auth.exception);

  RESULT_(CSTRING)
  passphrase =
      unseal_passphrase(srk_auth.value, pp_auth.value, sealed_pp.value);
  THROW(passphrase.exception);

  EXCLUDE(out_string("Please confirm that the passphrase is correct:\n\n");)
  EXCLUDE(out_string(passphrase.value);)
  EXCLUDE(
      out_string("\n\nIf this is correct, please type YES in all capitals: ");)

  EXCLUDE(char *yes_string = alloc(4); get_string(yes_string, 4, true);
          if (memcmp("YES", yes_string, 3)) reboot();)

  return ret;
}

#ifndef ISABELLE
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
  RESULT_(TPM_PCRVALUE) extend_ret;
  RESULT sha1_ret;
  SHA1_Context sctx;

  ERROR(~mbi->flags & (enum mbi_enum)MBI_FLAG_MODS, ERROR_BAD_MODULE,
        "module flag missing");
  ERROR(!mbi->mods_count, ERROR_NO_MODULE, "no module to hash");
  out_description("Hashing modules count", mbi->mods_count);

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

  struct module *a = (struct module *)(mbi->mods_addr);
  sha1_init(&sctx);
  sha1(&sctx, (BYTE *)mbi->cmdline, strLen((char *)mbi->cmdline));
  for (unsigned i = 0; i < mbi->mods_count; i++, a++)
    sha1(&sctx, (unsigned char *)a->string, strlen((char *)a->string) + 1);
  sha1_finish(&sctx);
  RESULT_(TPM_PCRVALUE) ext_ret = TPM_Extend(19, sctx.hash);
  THROW(ext_ret.exception);

  return ret;
}

/* EXCEPT:
 * ERROR_TPM
 * ERROR_TPM_BAD_OUTPUT_PARAM
 *
 * Prepare the TPM for late launch.
 * Returns a TIS_INIT_* value.
 */
static RESULT prepare_tpm(void) {
  RESULT ret = {.exception.error = NONE};
  enum TIS_TPM_VENDOR vendor;

  vendor = tis_init();
  ERROR(0 >= vendor, ERROR_BAD_TPM_VENDOR, "tis init failed");

  RESULT tis_access_ret = tis_access(TIS_LOCALITY_0, 0);
  CATCH(tis_access_ret.exception, ERROR_TIS_LOCALITY_ALREADY_ACCESSED,
        out_info("Already in Locality 0"));
  THROW(tis_access_ret.exception);

  RESULT tpm_startup_ret = TPM_Startup(TPM_ST_CLEAR);
  CATCH(tpm_startup_ret.exception, ERROR_TPM | TPM_E_INVALID_POSTINIT,
        out_info("TPM already initialized"));
  THROW(tpm_startup_ret.exception);

  RESULT tis_deactivate_res = tis_deactivate_all();
  THROW(tis_deactivate_res.exception);

  return ret;
}

/**
 * This function runs before the late launch and has to enable SVM in the
 * processor and disable all localities.
 */
RESULT pre_launch(struct mbi *m, unsigned flags) {
  RESULT ret = {.exception.error = NONE};
  out_string(version_string);

  ERROR(!m, ERROR_NO_MBI, "not loaded via multiboot");
  ERROR(flags != MBI_MAGIC2, ERROR_BAD_MBI, "not loaded via multiboot");

  // set bootloader name
  m->flags |= (enum mbi_enum)MBI_FLAG_BOOT_LOADER_NAME;
  m->boot_loader_name = (unsigned)version_string;

  RESULT tpm = prepare_tpm();
  THROW(tpm.exception);

#ifdef __ARCH_AMD__
  RESULT_(UINT32) cpuid = check_cpuid();
  THROW(cpuid.exception);
  out_description("SVM revision", cpuid.value);

  RESULT svm = enable_svm();
  THROW(svm.exception);
  RESULT sp = stop_processors();
  THROW(sp.exception);

  out_info("call skinit");
  wait(1000); // we need to wait to ensure that all APs have halted
  do_skinit();
#endif

  return ret;
}

void _pre_launch(struct mbi *m, unsigned flags) {
  RESULT res = pre_launch(m, flags);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });
}

/**
 * This code is executed after late launch.
 */
RESULT post_launch(struct mbi *m) {
  RESULT ret = {.exception.error = NONE};

#ifdef __ARCH_AMD__
  RESULT revert_skinit_ret = revert_skinit();
#ifdef TARGET_QEMU
  CATCH(revert_skinit_ret.exception, ERROR_DEV, );
#endif
  THROW(revert_skinit_ret.exception);
#endif

  // Finding NV Index
  int nvIndex = 0;
  char *val = cmdlineArgVal((char *)m->cmdline, "--nv-index=");
  while (val[0] != '\0' && val[0] != ' ') {
    nvIndex *= 10;
    nvIndex += (val[0] - '0');
    val++;
  }

  ERROR(!m, ERROR_NO_MBI, "no mbi in sable()");

  if (tis_init()) {
    RESULT tis_access_ret = tis_access(TIS_LOCALITY_2, 0);
    THROW(tis_access_ret.exception);
    RESULT mbi_calc_hash_ret = mbi_calc_hash(m);
    THROW(mbi_calc_hash_ret.exception);

#ifndef NDEBUG
    RESULT_(TPM_PCRVALUE) pcr17 = TPM_PCRRead(17);
    THROW(pcr17.exception);
    show_hash("PCR[17]: ", pcr17.value);

    RESULT_(TPM_PCRVALUE) pcr19 = TPM_PCRRead(19);
    THROW(pcr19.exception);
    show_hash("PCR[19]: ", pcr19.value);

    wait(1000);
#endif

    char config_str[2];
    out_string("Configure now? [y/n]: ");
    get_string(config_str, sizeof(config_str) - 1, true);
    if (config_str[0] == 'y') {
      RESULT configure_ret = configure(nvIndex);
      THROW(configure_ret.exception);
      RESULT tis_deactiv = tis_deactivate_all();
      THROW(tis_deactiv.exception);
      out_string("\nConfiguration complete. Rebooting now...\n");
      wait(5000);
      reboot();
    } else {
      RESULT trusted_boot_ret = trusted_boot(nvIndex);
      THROW(trusted_boot_ret.exception);
      RESULT tis_deactiv = tis_deactivate_all();
      THROW(tis_deactiv.exception);
    }
  }

  RESULT start_module_ret = start_module(m);
  THROW(start_module_ret.exception);

  return ret;
}

void _post_launch(struct mbi *m) {
  RESULT res = post_launch(m);
  CATCH_ANY(res.exception, {
    dump_exception(res.exception);
    exit(res.exception.error);
  });
}
#endif
