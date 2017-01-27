#include "sable_verified.h"
#include "string.h"

#define SLB_PCR_ORD 17
#define MODULE_PCR_ORD 19

/***********************************************************
 * SABLE globals
 **********************************************************/

/* plaintext global secrets */
static struct {
  TPM_AUTHDATA pp_auth;
  TPM_AUTHDATA srk_auth;
  char passphrase[PASSPHRASE_STR_SIZE];
} secrets;

/* ciphertext global secrets */
static TPM_STORED_DATA12 pp_data;
static BYTE pp_blob[400];

extern void get_authdata(const char *str /* in */,
                         TPM_AUTHDATA *authdata /* out */);

void configure(void) {
  /* local secrets */
  static TPM_AUTHDATA nv_auth;
  static TPM_SECRET sharedSecret;
  /* other static locals */
  static TPM_OSAP_SESSION srk_osap_session;
  static TPM_SESSION nv_session;
  static TPM_SECRET encAuth;
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
  /* auto locals */
  TPM_RESULT res;

  // Construct pcr_info, which contains the TPM state conditions under which
  // the passphrase may be sealed/unsealed
  res = TPM_PCRRead(17, &pcr_values[0]);
  TPM_ERROR(res, "Failed to read PCR17");
  res = TPM_PCRRead(19, &pcr_values[1]);
  TPM_ERROR(res, "Failed to read PCR19");
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
      pcr_info_packed, sizeof(pcr_info_packed), &pcr_info);
  assert(bytes_packed == sizeof(pcr_info_packed));

  // get the passphrase, passphrase authdata, and SRK authdata
  out_string(s_Please_enter_the_passphrase);
  UINT32 lenPassphrase =
      get_string(secrets.passphrase, sizeof(secrets.passphrase) - 1, true) + 1;
  get_authdata(s_enter_passPhraseAuthData, &secrets.pp_auth);
  get_authdata(s_enter_srkAuthData, &secrets.srk_auth);

  // Initialize an OSAP session for the SRK
  res = TPM_GetRandom(srk_osap_session.nonceOddOSAP.nonce, sizeof(TPM_NONCE));
  TPM_ERROR(res, s_nonce_generation_failed);
  res = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, &srk_osap_session);
  TPM_ERROR(res, s_TPM_Start_OSAP);
  srk_osap_session.session.continueAuthSession = FALSE;

  // Generate the shared secret (for SRK authorization)
  sharedSecret_gen(&sharedSecret, &secrets.srk_auth,
                   &srk_osap_session.nonceEvenOSAP,
                   &srk_osap_session.nonceOddOSAP);

  // Generate nonceOdd
  res =
      TPM_GetRandom(srk_osap_session.session.nonceOdd.nonce, sizeof(TPM_NONCE));
  TPM_ERROR(res, s_nonce_generation_failed);

  // Encrypt the new passphrase authdata
  encAuth_gen(&encAuth, &secrets.pp_auth, &sharedSecret,
              &srk_osap_session.session.nonceEven);

  // Encrypt the passphrase using the SRK
  res = TPM_Seal(&pp_data, pp_blob, sizeof(pp_blob), TPM_KH_SRK, encAuth,
                 pcr_info_packed, sizeof(pcr_info_packed),
                 (const BYTE *)secrets.passphrase, lenPassphrase,
                 &srk_osap_session.session, &sharedSecret);
  TPM_ERROR(res, s_TPM_Seal);

  get_authdata(s_enter_nvAuthData, &nv_auth);
  res = TPM_OIAP(&nv_session);
  TPM_ERROR(res, s_TPM_Start_OIAP);

  res = TPM_NV_WriteValueAuth(pp_blob, sizeof(pp_blob), 0x04, 0, &nv_auth,
                              &nv_session);
  TPM_ERROR(res, s_TPM_NV_WriteValueAuth);
}
