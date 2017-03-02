#ifndef ISABELLE
#include "asm.h"
#include "option.h"
#include "platform.h"
#include "alloc.h"
#include "exception.h"
#include "dev.h"
#include "mbi.h"
#include "elf.h"
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
#endif

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

LOCAL extern RESULT_(TPM_AUTHDATA) get_authdata(void);
LOCAL extern RESULT_(TPM_NONCE) get_nonce(void);

static TPM_SESSION *sessions[2] = {NULL, NULL};

LOCAL RESULT_GEN(TPM_PCR_INFO_LONG);
LOCAL RESULT_GEN(TPM_NONCE);
LOCAL RESULT_GEN(TPM_AUTHDATA);

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

  // Encrypt the passphrase using the SRK
  return TPM_Seal(TPM_KH_SRK, encAuth, pcr_info.value, (const BYTE *)passphrase,
                  lenPassphrase, &sessions[0], sharedSecret);
}

static RESULT write_passphrase(TPM_AUTHDATA nv_auth,
                               TPM_STORED_DATA12 sealedData) {
  RESULT ret = {.exception.error = NONE};

  RESULT oiap_ret = TPM_OIAP(&sessions[0]);
  THROW(oiap_ret.exception);
  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  struct extracted_TPM_STORED_DATA12 x = extract_TPM_STORED_DATA12(sealedData);
  return TPM_NV_WriteValueAuth(x.data, x.dataSize, 0x04, 0, nv_auth,
                               &sessions[0]);
}

RESULT configure(void) {
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
  return write_passphrase(nv_auth.value, sealedData.value);
}

static RESULT_(TPM_STORED_DATA12) read_passphrase(void) {
#ifdef NV_OWNER_REQUIRED
  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  RESULT_(TPM_AUTHDATA) nv_auth_ret = get_authdata();
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), nv_auth_ret.exception);

  const OPTION(TPM_AUTHDATA) nv_auth = {
    .value = nv_auth_ret.value,
    .hasValue = true};

  RESULT owner_oiap_ret = TPM_OIAP(&sessions[0]);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), owner_oiap_ret.exception);
  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  RESULT_(HEAP_DATA) val = TPM_NV_ReadValue(4, 0, 400, nv_auth, &sessions[0]);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), val.exception);
#else
  const OPTION(TPM_AUTHDATA) nv_auth = {.hasValue = false};

  RESULT_(HEAP_DATA) val = TPM_NV_ReadValue(4, 0, 400, nv_auth, NULL);
  THROW_TYPE(RESULT_(TPM_STORED_DATA12), val.exception);
#endif
  return (RESULT_(TPM_STORED_DATA12)){
      .exception.error = NONE,
      .value = unpack_TPM_STORED_DATA12(val.value.data, val.value.dataSize)};
}

typedef const char *CSTRING;
LOCAL RESULT_GEN(CSTRING);

static RESULT_(CSTRING)
    unseal_passphrase(TPM_AUTHDATA srk_auth, TPM_AUTHDATA pp_auth,
                      TPM_STORED_DATA12 sealed_pp) {
  RESULT_(CSTRING) ret = {.exception.error = NONE};

  RESULT srk_oiap_ret = TPM_OIAP(&sessions[0]);
  THROW(srk_oiap_ret.exception);
  RESULT_(TPM_NONCE) nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[0]->nonceOdd = nonceOdd.value;
  sessions[0]->continueAuthSession = FALSE;

  RESULT pp_oiap_ret = TPM_OIAP(&sessions[1]);
  THROW(pp_oiap_ret.exception);
  nonceOdd = get_nonce();
  THROW(nonceOdd.exception);
  sessions[1]->nonceOdd = nonceOdd.value;
  sessions[1]->continueAuthSession = FALSE;

  RESULT_(HEAP_DATA)
  unseal_ret = TPM_Unseal(sealed_pp, TPM_KH_SRK, srk_auth, &sessions[0],
                          pp_auth, &sessions[1]);
  THROW(unseal_ret.exception);
  ret.value = (CSTRING)unseal_ret.value.data;

  return ret;
}

RESULT trusted_boot(void) {
  RESULT ret = {.exception.error = NONE};
  RESULT_(TPM_STORED_DATA12) sealed_pp = read_passphrase();
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
