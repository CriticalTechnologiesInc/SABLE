#include "platform.h"
#include "keyboard.h"
#include "tcg.h"
#include "util.h"
#include "version.h"
#include "string.h"

#define DEFINE_STRING(name, str) const char *const s_##name = str

#define xstr(s) str(s)
#define str(s) #s

DEFINE_STRING(TPM_Start_OSAP, "TPM_Start_OSAP()");
DEFINE_STRING(TPM_Seal, "TPM_Seal()");
DEFINE_STRING(TPM_Start_OIAP, "TPM_Start_OIAP()");
DEFINE_STRING(TPM_NV_WriteValueAuth, "TPM_NV_WriteValueAuth()");
DEFINE_STRING(
    Please_enter_the_passphrase,
    "Please enter the passphrase (" xstr(PASSPHRASE_STR_SIZE) " char max): ");
DEFINE_STRING(nonce_generation_failed, "nonce generation failed");
DEFINE_STRING(enter_srkAuthData, "Please enter the srkAuthData (" xstr(
                                     AUTHDATA_STR_SIZE) " char max): ");
DEFINE_STRING(enter_passPhraseAuthData,
              "Please enter the passPhraseAuthData (" xstr(
                  AUTHDATA_STR_SIZE) " char max): ");
DEFINE_STRING(enter_nvAuthData, "Please enter the NVRAM password (" xstr(
                                    AUTHDATA_STR_SIZE) " char max): ");
