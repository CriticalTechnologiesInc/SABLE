#define DECLARE_STRING(name) extern const char *const s_##name

#define PASSPHRASE_STR_SIZE 128
#define AUTHDATA_STR_SIZE 64

DECLARE_STRING(TPM_Start_OSAP);
DECLARE_STRING(TPM_Seal);
DECLARE_STRING(TPM_Start_OIAP);
DECLARE_STRING(TPM_NV_WriteValueAuth);
DECLARE_STRING(Please_enter_the_passphrase);
DECLARE_STRING(nonce_generation_failed);
DECLARE_STRING(enter_srkAuthData);
DECLARE_STRING(enter_passPhraseAuthData);
DECLARE_STRING(enter_nvAuthData);
