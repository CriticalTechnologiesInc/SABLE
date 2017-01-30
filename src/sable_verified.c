#include "sable_verified.h"

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

extern TPM_AUTHDATA get_authdata(void);
extern TPM_NONCE get_nonce(void);

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

// Construct pcr_info, which contains the TPM state conditions under which
// the passphrase may be sealed/unsealed
void set_pcr_info(void) {
  struct TPM_PCRRead_ret pcr17 = TPM_PCRRead(17);
  TPM_ERROR(pcr17.returnCode, "Failed to read PCR17");
  pcr_values[0] = pcr17.outDigest;
  struct TPM_PCRRead_ret pcr19 = TPM_PCRRead(19);
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
}

void configure(void) {
  TPM_RESULT res;

  // get the passphrase, passphrase authdata, and SRK authdata
  EXCLUDE(out_string("Please enter the passphrase (" xstr(
      PASSPHRASE_STR_SIZE) " char max): ");)
  UINT32 lenPassphrase =
      get_string(passphrase, sizeof(passphrase) - 1, true) + 1;
  EXCLUDE(out_string("Please enter the passPhraseAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA pp_auth = get_authdata();
  EXCLUDE(out_string("Please enter the srkAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA srk_auth = get_authdata();

  // Initialize an OSAP session for the SRK
  srk_osap_session.nonceOddOSAP = get_nonce();
  res = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, &srk_osap_session);
  TPM_ERROR(res, "TPM_Start_OSAP()");
  srk_osap_session.session.continueAuthSession = FALSE;

  // Generate the shared secret (for SRK authorization)
  TPM_SECRET sharedSecret = sharedSecret_gen(
      srk_auth, srk_osap_session.nonceEvenOSAP, srk_osap_session.nonceOddOSAP);

  // Generate nonceOdd
  srk_osap_session.session.nonceOdd = get_nonce();

  // Encrypt the new passphrase authdata
  TPM_ENCAUTH encAuth =
      encAuth_gen(pp_auth, sharedSecret, srk_osap_session.session.nonceEven);

  // Encrypt the passphrase using the SRK
  struct TPM_Seal_ret seal_ret =
      TPM_Seal(pp_blob, sizeof(pp_blob), TPM_KH_SRK, encAuth, pcr_info_packed,
               sizeof(pcr_info_packed), (const BYTE *)passphrase, lenPassphrase,
               &srk_osap_session.session, sharedSecret);
  TPM_ERROR(seal_ret.returnCode, "TPM_Seal()");

  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA nv_auth = get_authdata();
  res = TPM_OIAP(&nv_session);
  TPM_ERROR(res, "TPM_Start_OIAP()");

  res = TPM_NV_WriteValueAuth(pp_blob, sizeof(pp_blob), 0x04, 0, nv_auth,
                              &nv_session);
  TPM_ERROR(res, "TPM_NV_WriteValueAuth()");
}
