#include "sable_verified.h"
#include "../include/asm.h"
#include "../include/alloc.h"

BYTE *mgf1(BYTE *input, UINT32 inputLen, UINT32 outputLen) {

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

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

typedef TPM_SEALED_DATA
    BOGUS1; // just to get makeheaders to include TPM_SEALED_DATA

extern TPM_AUTHDATA get_authdata(void);
extern TPM_NONCE get_nonce(void);

static TPM_SESSION *sessions[2] = {NULL, NULL};

// Construct pcr_info, which contains the TPM state conditions under which
// the passphrase may be sealed/unsealed
TPM_PCR_INFO_LONG get_pcr_info(void) {
  TPM_PCRVALUE *pcr_values = alloc(2 * sizeof(TPM_PCRVALUE));
  BYTE *pcr_select_bytes = alloc(3);
  pcr_select_bytes[0] = 0x00;
  pcr_select_bytes[1] = 0x00;
  pcr_select_bytes[2] = 0x0a;
  TPM_PCR_SELECTION pcr_select = {.sizeOfSelect = 3,
                                  .pcrSelect = (BYTE *)pcr_select_bytes};
  struct TPM_PCRRead_ret pcr17 = TPM_PCRRead(17);
  TPM_ERROR(pcr17.returnCode, TPM_PCRRead);
  pcr_values[0] = pcr17.outDigest;
  struct TPM_PCRRead_ret pcr19 = TPM_PCRRead(19);
  TPM_ERROR(pcr19.returnCode, TPM_PCRRead);
  pcr_values[1] = pcr19.outDigest;
  TPM_PCR_COMPOSITE composite = {.select = pcr_select,
                                 .valueSize = 2 * sizeof(TPM_PCRVALUE),
                                 .pcrValue = (TPM_PCRVALUE *)pcr_values};
  TPM_COMPOSITE_HASH composite_hash = get_TPM_COMPOSITE_HASH(composite);
  TPM_PCR_INFO_LONG pcr_info = {.tag = TPM_TAG_PCR_INFO_LONG,
                                .localityAtCreation = TPM_LOC_TWO,
                                .localityAtRelease = TPM_LOC_TWO,
                                .creationPCRSelection = pcr_select,
                                .releasePCRSelection = pcr_select,
                                .digestAtCreation = composite_hash,
                                .digestAtRelease = composite_hash};
  return pcr_info;
}

TPM_STORED_DATA12 seal_passphrase(TPM_AUTHDATA srk_auth, TPM_AUTHDATA pp_auth,
                                  const char *passphrase,
                                  UINT32 lenPassphrase) {
  TPM_RESULT res;

  // Initialize an OSAP session for the SRK
  TPM_NONCE nonceOddOSAP = get_nonce();
  res = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, nonceOddOSAP, &sessions[0]);
  TPM_ERROR(res, TPM_Start_OSAP);
  sessions[0]->nonceOdd = get_nonce();
  sessions[0]->continueAuthSession = FALSE;

  // Generate the shared secret (for SRK authorization)
  TPM_SECRET sharedSecret =
      sharedSecret_gen(srk_auth, sessions[0]->osap->nonceEvenOSAP,
                       sessions[0]->osap->nonceOddOSAP);

  // Encrypt the new passphrase authdata
  TPM_ENCAUTH encAuth =
      encAuth_gen(pp_auth, sharedSecret, sessions[0]->nonceEven);

  TPM_PCR_INFO_LONG pcr_info = get_pcr_info();

  /* MGF1 Mask Generation and XOR
  UINT32 seedLen = sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3 +
  sizeof(TPM_SECRET);
  BYTE *seed = alloc(seedLen);
  memcpy(seed, &sessions[0]->nonceEven, sizeof(TPM_NONCE));
  memcpy(seed+sizeof(TPM_NONCE), &sessions[0]->nonceOdd, sizeof(TPM_NONCE));
  memcpy(seed+sizeof(TPM_NONCE)+sizeof(TPM_NONCE), (BYTE *) "XOR", 3);
  memcpy(seed+sizeof(TPM_NONCE)+sizeof(TPM_NONCE)+3, &sharedSecret,
  sizeof(TPM_SECRET));
  const BYTE *mask = mgf1(seed, seedLen, lenPassphrase);
  BYTE *passEnc = alloc(lenPassphrase);
  do_xor((const BYTE *) passphrase, mask, passEnc, lenPassphrase);
  */

  // Encrypt the passphrase using the SRK
  struct TPM_Seal_ret seal_ret = TPM_Sealx(
      TPM_KH_SRK, encAuth, pcr_info, (const BYTE *)passphrase /*passEnc*/,
      lenPassphrase, &sessions[0], sharedSecret);
  TPM_ERROR(seal_ret.returnCode, TPM_Seal);

  return seal_ret.sealedData;
}

void write_passphrase(TPM_AUTHDATA nv_auth, TPM_STORED_DATA12 sealedData,
                      UINT32 index) {
  TPM_RESULT res;

  res = TPM_OIAP(&sessions[0]);
  TPM_ERROR(res, TPM_Start_OIAP);
  sessions[0]->nonceOdd = get_nonce();
  sessions[0]->continueAuthSession = FALSE;

  struct extracted_TPM_STORED_DATA12 x = extract_TPM_STORED_DATA12(sealedData);
  res = TPM_NV_WriteValueAuth(x.data, x.dataSize, index, 0, nv_auth,
                              &sessions[0]);
  TPM_ERROR(res, TPM_NV_WriteValueAuth);
}

void configure(UINT32 index) {
  char *passphrase = alloc(PASSPHRASE_STR_SIZE);

  // get the passphrase, passphrase authdata, and SRK authdata
  EXCLUDE(out_string("Please enter the passphrase (" xstr(
      PASSPHRASE_STR_SIZE) " char max): ");)
  UINT32 lenPassphrase =
      get_string(passphrase, PASSPHRASE_STR_SIZE - 1, true) + 1;
  EXCLUDE(out_string("Please enter the passPhraseAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA pp_auth = get_authdata();
  EXCLUDE(out_string("Please enter the srkAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA srk_auth = get_authdata();

  // seal the passphrase to the pp_blob buffer
  TPM_STORED_DATA12 sealedData =
      seal_passphrase(srk_auth, pp_auth, passphrase, lenPassphrase);

  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA nv_auth = get_authdata();

  // write the sealed passphrase to disk
  write_passphrase(nv_auth, sealedData, index);
}

TPM_STORED_DATA12 read_passphrase(UINT32 index) {
  struct TPM_NV_ReadValue_ret val;
  OPTION(TPM_AUTHDATA) nv_auth;

#ifdef NV_OWNER_REQUIRED
  EXCLUDE(out_string("Please enter the nvAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  nv_auth.value = get_authdata();
  nv_auth.hasValue = true;

  TPM_SESSION *owner_session = &sessions[0];
  res = TPM_OIAP(&owner_session);
  TPM_ERROR(res, TPM_OIAP);
  owner_session->nonceOdd = get_nonce();
  owner_session->continueAuthSession = FALSE;

  val = TPM_NV_ReadValue(index, 0, 400, nv_auth, nv_session);
  TPM_ERROR(val.returnCode, TPM_NV_ReadValue);
#else
  nv_auth.hasValue = false;
  val = TPM_NV_ReadValue(index, 0, 400, nv_auth, NULL);
  TPM_ERROR(val.returnCode, TPM_NV_ReadValue);
#endif

  return unpack_TPM_STORED_DATA12(val.data, val.dataSize);
}

const char *unseal_passphrase(TPM_AUTHDATA srk_auth, TPM_AUTHDATA pp_auth,
                              TPM_STORED_DATA12 sealed_pp) {
  TPM_RESULT res;

  /*
  res = TPM_OIAP(&sessions[0]);
  TPM_ERROR(res, TPM_OIAP);
  sessions[0]->nonceOdd = get_nonce();
  sessions[0]->continueAuthSession = FALSE;
  */

  TPM_NONCE nonceOddOSAP = get_nonce();
  res = TPM_OSAP(TPM_ET_KEYHANDLE, TPM_KH_SRK, nonceOddOSAP, &sessions[0]);
  TPM_ERROR(res, TPM_Start_OSAP);
  sessions[0]->nonceOdd = get_nonce();
  sessions[0]->continueAuthSession = FALSE;
  TPM_SECRET sharedSecret =
      sharedSecret_gen(srk_auth, sessions[0]->osap->nonceEvenOSAP,
                       sessions[0]->osap->nonceOddOSAP);

  res = TPM_OIAP(&sessions[1]);
  TPM_ERROR(res, TPM_OIAP);
  sessions[1]->nonceOdd = get_nonce();
  sessions[1]->continueAuthSession = FALSE;

  // TPM_NONCE authLastNonceEven = sessions[0]->nonceEven;

  TPM_Unseal_ret unseal_ret = TPM_Unseal(sealed_pp, TPM_KH_SRK, sharedSecret,
                                         &sessions[0], pp_auth, &sessions[1]);
  TPM_ERROR(unseal_ret.returnCode, TPM_Unseal);
  /*
  UINT32 seedLen = sizeof(TPM_NONCE) + sizeof(TPM_NONCE) + 3 +
  sizeof(TPM_SECRET);
  BYTE *seed = alloc(seedLen);
  memcpy(seed, &authLastNonceEven, sizeof(TPM_NONCE));
  memcpy(seed+sizeof(TPM_NONCE), &sessions[0]->nonceOdd, sizeof(TPM_NONCE));
  memcpy(seed+sizeof(TPM_NONCE)+sizeof(TPM_NONCE), (BYTE *) "XOR", 3);
  memcpy(seed+sizeof(TPM_NONCE)+sizeof(TPM_NONCE)+3, &sharedSecret,
  sizeof(TPM_SECRET));
  const BYTE *mask = mgf1(seed, seedLen, unseal_ret.dataSize);
  BYTE *passUnc = alloc(unseal_ret.dataSize);
  do_xor(unseal_ret.data, mask, passUnc, unseal_ret.dataSize);
  */
  return (const char *)unseal_ret.data;
  // return (const char *) passUnc;
}

void trusted_boot(UINT32 index) {
  TPM_STORED_DATA12 sealed_pp = read_passphrase(index);

  EXCLUDE(out_string("Please enter the passPhraseAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA pp_auth = get_authdata();
  EXCLUDE(out_string("Please enter the srkAuthData (" xstr(
      AUTHDATA_STR_SIZE) " char max): ");)
  TPM_AUTHDATA srk_auth = get_authdata();

  const char *passphrase = unseal_passphrase(srk_auth, pp_auth, sealed_pp);

  EXCLUDE(out_string("Please confirm that the passphrase is correct:\n\n");)
  EXCLUDE(out_string(passphrase);)
  EXCLUDE(
      out_string("\n\nIf this is correct, please type YES in all capitals: ");)

  EXCLUDE(char *yes_string = alloc(4); get_string(yes_string, 4, true);

          if (memcmp("YES", yes_string, 3)) reboot();)
}
