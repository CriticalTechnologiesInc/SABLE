#include "sable_verified.h"
#include "string.h"

extern TPM_AUTHDATA get_authdata(const char *str /* in */);

/***********************************************************
 * SABLE globals
 **********************************************************/

static char passphrase[PASSPHRASE_STR_SIZE];
static BYTE pp_blob[400];
static BYTE pcr_select_bytes[3] = {0x0, 0x0, 0xa};
static const TPM_PCR_SELECTION pcr_select = {
    .sizeOfSelect = sizeof(pcr_select_bytes),
    .pcrSelect = (BYTE *)pcr_select_bytes};
static TPM_PCRVALUE pcr_values[2];
static BYTE pcr_info_packed[sizeof(TPM_STRUCTURE_TAG) +
                            2 * sizeof(TPM_LOCALITY_SELECTION) +
                            2 * (sizeof(pcr_select.sizeOfSelect) +
                                 sizeof(pcr_select_bytes)) +
                            2 * sizeof(TPM_COMPOSITE_HASH)];

/* TPM sessions */
static TPM_OSAP_SESSION srk_osap_session;
static TPM_SESSION nv_session;

void configure(void) {
  TPM_RESULT res;

  // Construct pcr_info, which contains the TPM state conditions under which
  // the passphrase may be sealed/unsealed
  TPM_PCRRead_t pcr17 = TPM_PCRRead(17);
  TPM_ERROR(pcr17.returnCode, "Failed to read PCR17");
  pcr_values[0] = pcr17.outDigest;
  TPM_PCRRead_t pcr19 = TPM_PCRRead(19);
  TPM_ERROR(pcr19.returnCode, "Failed to read PCR19");
  pcr_values[1] = pcr19.outDigest;
  TPM_PCR_COMPOSITE composite = {.select = pcr_select,
                                 .valueSize = sizeof(pcr_values),
                                 .pcrValue = (TPM_PCRVALUE *)pcr_values};
  TPM_COMPOSITE_HASH composite_hash = get_TPM_COMPOSITE_HASH(composite);
  TPM_PCR_INFO_LONG pcr_info = {.tag = TPM_TAG_PCR_INFO_LONG,
                                .localityAtCreation = TPM_LOC_TWO,
                                .localityAtRelease = TPM_LOC_TWO,
                                .creationPCRSelection = pcr_select,
                                .releasePCRSelection = pcr_select,
                                .digestAtCreation = composite_hash,
                                .digestAtRelease = composite_hash};
  UINT32 bytes_packed = pack_TPM_PCR_INFO_LONG(
      pcr_info_packed, sizeof(pcr_info_packed), pcr_info);
  assert(bytes_packed == sizeof(pcr_info_packed));

  // get the passphrase, passphrase authdata, and SRK authdata
  out_string(s_Please_enter_the_passphrase);
  UINT32 lenPassphrase =
      get_string(passphrase, sizeof(passphrase) - 1, true) + 1;
  TPM_AUTHDATA pp_auth = get_authdata(s_enter_passPhraseAuthData);
  TPM_AUTHDATA srk_auth = get_authdata(s_enter_srkAuthData);

  // Initialize an OSAP session for the SRK
  res = TPM_GetRandom(srk_osap_session.nonceOddOSAP.nonce, sizeof(TPM_NONCE));
  TPM_ERROR(res, s_nonce_generation_failed);
  res = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, &srk_osap_session);
  TPM_ERROR(res, s_TPM_Start_OSAP);
  srk_osap_session.session.continueAuthSession = FALSE;

  // Generate the shared secret (for SRK authorization)
  TPM_SECRET sharedSecret = sharedSecret_gen(
      srk_auth, srk_osap_session.nonceEvenOSAP, srk_osap_session.nonceOddOSAP);

  // Generate nonceOdd
  res =
      TPM_GetRandom(srk_osap_session.session.nonceOdd.nonce, sizeof(TPM_NONCE));
  TPM_ERROR(res, s_nonce_generation_failed);

  // Encrypt the new passphrase authdata
  TPM_ENCAUTH encAuth =
      encAuth_gen(pp_auth, sharedSecret, srk_osap_session.session.nonceEven);

  // Encrypt the passphrase using the SRK
  TPM_Seal_t seal_ret = TPM_Seal(pp_blob, sizeof(pp_blob), TPM_KH_SRK, encAuth,
                 pcr_info_packed, sizeof(pcr_info_packed),
                 (const BYTE *)passphrase, lenPassphrase,
                 &srk_osap_session.session, sharedSecret);
  TPM_ERROR(seal_ret.returnCode, s_TPM_Seal);

  TPM_AUTHDATA nv_auth = get_authdata(s_enter_nvAuthData);
  res = TPM_OIAP(&nv_session);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_NV_WriteValueAuth(pp_blob, sizeof(pp_blob), 0x04, 0, nv_auth,
                              &nv_session);
  TPM_ERROR(res, s_TPM_NV_WriteValueAuth);
}
