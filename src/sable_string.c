#include "platform.h"
#include "keyboard.h"
#include "tcg.h"
#include "util.h"
#include "version.h"
#include "sable_defs.h"
#include "sable_string.h"

#ifdef EXEC
#define DEFINE_STRING(name, str) const char *const s_##name = str
#else
#define DEFINE_STRING(name, str) const char *const s_##name = 0
#endif

#define xstr(s) str(s)
#define str(s) #s

DEFINE_STRING(WARNING, "\nWARNING: ");
DEFINE_STRING(dashes, " -- ");
DEFINE_STRING(ERROR, "\nERROR: ");
DEFINE_STRING(TPM_Start_OSAP, "TPM_Start_OSAP()");
DEFINE_STRING(TPM_Seal, "TPM_Seal()");
DEFINE_STRING(TPM_NV_DefineSpace, "TPM_NV_DefineSpace()");
DEFINE_STRING(TPM_Start_OIAP, "TPM_Start_OIAP()");
DEFINE_STRING(TPM_NV_WriteValueAuth, "TPM_NV_WriteValueAuth()");
DEFINE_STRING(TPM_NV_ReadValueAuth, "TPM_NV_ReadValueAuth()");
DEFINE_STRING(TPM_Unseal, "TPM_Unseal()");
DEFINE_STRING(Please_confirm_that_the_passphrase,
              "\nPlease confirm that the passphrase shown below matches the "
              "one which was entered during system configuration. If the "
              "passphrase does not match, contact your systems administrator "
              "immediately.\n\n");
DEFINE_STRING(Passphrase, "Passphrase: ");
DEFINE_STRING(If_this_is_correct,
              "\n\nIf this is correct, type 'yes' in all capitals: ");
DEFINE_STRING(YES, "YES");
DEFINE_STRING(module_flag_missing, "module flag missing");
DEFINE_STRING(no_module_to_hash, "no module to hash");
DEFINE_STRING(Hashing_modules_count, "Hashing modules count:");
DEFINE_STRING(config_magic_detected, "config magic detected");
DEFINE_STRING(
    Please_enter_the_passphrase,
    "Please enter the passphrase (" xstr(PASSPHRASE_STR_SIZE) " char max): ");
DEFINE_STRING(mod_end_less_than_start, "mod_end less than start");
DEFINE_STRING(TPM_Extend, "TPM_Extend()");
DEFINE_STRING(tis_init_failed, "tis init failed");
DEFINE_STRING(could_not_gain_tis_ownership, "could not gain TIS ownership");
DEFINE_STRING(TPM_Startup_Clear, "TPM_Startup_Clear()");
DEFINE_STRING(not_loaded_via_multiboot, "not loaded via multiboot");
DEFINE_STRING(No_SVM_platform, "No SVM platform");
DEFINE_STRING(Could_not_prepare_TPM, "Could not prepare the TPM");
DEFINE_STRING(start_module_failed, "start module failed");
DEFINE_STRING(sending_an_INIT_IPI,
              "sending an INIT IPI to other processors failed");
DEFINE_STRING(call_skinit, "call skinit");
DEFINE_STRING(SVM_revision, "SVM revision:");
DEFINE_STRING(nonce_generation_failed, "nonce generation failed");
DEFINE_STRING(no_mbi_in_sable, "no mbi in sable()");
DEFINE_STRING(enter_srkAuthData, "Please enter the srkAuthData (" xstr(
                                     AUTHDATA_STR_SIZE) " char max): ");
DEFINE_STRING(enter_passPhraseAuthData,
              "Please enter the passPhraseAuthData (" xstr(
                  AUTHDATA_STR_SIZE) " char max): ");
DEFINE_STRING(could_not_gain_TIS_ownership, "could not gain TIS ownership");
DEFINE_STRING(TPM_PcrRead, "TPM_PcrRead()");
DEFINE_STRING(PCR17, "PCR[17]: ");
DEFINE_STRING(PCR19, "PCR[19]: ");
DEFINE_STRING(calc_hash_failed, "calc hash failed");
DEFINE_STRING(enter_nvAuthData, "Please enter the NVRAM password (" xstr(
                                    AUTHDATA_STR_SIZE) " char max): ");
DEFINE_STRING(tis_deactivate_failed, "tis deactivate failed");
DEFINE_STRING(Configuration_complete_Rebooting_now,
              "\nConfiguration complete. Rebooting now...\n");
DEFINE_STRING(version_string,
              "SABLE:   v." SABLE_VERSION_MAJOR "." SABLE_VERSION_MINOR "\n");
