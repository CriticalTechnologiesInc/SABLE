#include "string.h"

#ifdef EXEC
#define DEFINE_STRING(name, str) const char *const s_##name = str
#else
#define DEFINE_STRING(name, str) const char *const s_##name = 0
#endif

DEFINE_STRING(no_capability_list_support, "no capability list support");
DEFINE_STRING(SHA_data_exceeds_maximum_size, "SHA data exceeds maximum size");
DEFINE_STRING(exit, "exit()");
DEFINE_STRING(reboot_now, "-> OK, reboot now!\n");
DEFINE_STRING(no_ext_cpuid, "no ext cpuid");
DEFINE_STRING(no_SVM_support, "no SVM support");
DEFINE_STRING(no_APIC_support, "no APIC support");
DEFINE_STRING(could_not_enable_SVM, "could not enable SVM");
DEFINE_STRING(pci_debug_format_string, "    %c: %#x%x/%#x%x");
DEFINE_STRING(device_not_found, "device not found");
DEFINE_STRING(cap_not_found, "cap not found");
DEFINE_STRING(invalid_DEV_HDR, "invalid DEV_HDR");
DEFINE_STRING(disable_DEV_and_SLDEV_protection,
              "disable DEV and SLDEV protection");
DEFINE_STRING(DEV_not_found, "DEV not found");
DEFINE_STRING(enable_dev_at, "enable dev at");
DEFINE_STRING(enable_DEV_protection, "enable DEV protection");
DEFINE_STRING(dev_pointer_invalid, "dev pointer invalid");
DEFINE_STRING(sldev_pointer_invalid, "sldev pointer invalid");
DEFINE_STRING(not_BSP_or_APIC_disabled, "not BSP or APIC disabled");
DEFINE_STRING(APIC_out_of_range, "APIC out of range");
DEFINE_STRING(Interrupt_pending, "Interrupt pending");
DEFINE_STRING(No_module_to_start, "No module to start.\n");
DEFINE_STRING(elf_magic, "elf magic:");
DEFINE_STRING(elf_class_data, "elf class_data:");
DEFINE_STRING(ELF_header_incorrect, "ELF header incorrect");
DEFINE_STRING(ELF_type_incorrect, "ELF type incorrect");
DEFINE_STRING(e_phentsize_too_small, "e_phentsize to small");
DEFINE_STRING(jumping_to_next_segment, "jumping to next segment...\n");
DEFINE_STRING(address_d_not_aligned_or_larger_than_1MB,
              "address %d not aligned or larger then 1MB");
DEFINE_STRING(configmagic, "SABLECONFIG");
DEFINE_STRING(WARNING, "\nWARNING: ");
DEFINE_STRING(dashes, " -- ");
DEFINE_STRING(ERROR, "\nERROR: ");
DEFINE_STRING(TPM_Start_OIAP_failed_on_transmit, "TPM_Start_OIAP() failed on transmit");
DEFINE_STRING(TPM_Unseal_failed_on_transmit, "TPM_Unseal() failed on transmit");
DEFINE_STRING(secret_data_too_big_for_buffer, "secret data too big for buffer");
DEFINE_STRING(could_not_get_random_number_from_TPM, "could not get random num from TPM");
DEFINE_STRING(TPM_NV_DefineSpace_failed_on_transmit, "TPM_NV_DefineSpace() failed on transmit");
DEFINE_STRING(TPM_NV_ReadValueAuth_failed_on_transmit, "TPM_NV_ReadValueAuth() failed on transmit");
DEFINE_STRING(buffer_overflow_detected, "\nBuffer overflow detected\n");
DEFINE_STRING(TPM_NV_WriteValueAuth_failed_on_transmit, "TPM_NV_WriteValueAuth() failed on transmit");
DEFINE_STRING(TPM_Flush_failed_on_transmit, "TPM_Flush() failed on transmit");
DEFINE_STRING(TPM_Seal_failed_on_transmit, "TPM_Seal() failed on transmit");
DEFINE_STRING(TPM_GetRandom_failed_on_transmit, "TPM_GetRandom() failed on transmit");
DEFINE_STRING(could_not_get_enough_random_bytes_from_TPM, "could not get enough random bytes from TPM");
DEFINE_STRING(TPM_PcrRead_failed_on_transmit, "TPM_PcrRead() failed on transmit");
DEFINE_STRING(TPM_Extend_failed_on_transmit, "TPM_Extend() failed on transmit");
DEFINE_STRING(TPM_Start_OSAP_failed_on_transmit, "TPM_Start_OSAP() failed on transmit");
DEFINE_STRING(TPM_Startup_failed_on_transmit, "TPM_Startup() failed on transmit");
DEFINE_STRING(TPM_GetCapability_Pcrs_failed, "TPM_GetCapability_Pcrs() failed");
DEFINE_STRING(PCRs, "PCRs:");
DEFINE_STRING(TPM_PcrRead_failed_with, "\nTPM_PcrRead() failed with");
DEFINE_STRING(left_bracket, " [");
DEFINE_STRING(right_bracket, "]: ");
DEFINE_STRING(Fix_DID_VID_bug, "Fix DID/VID bug...");
DEFINE_STRING(STM_rev, "STM rev:");
DEFINE_STRING(Infineon_rev, "Infineon rev:");
DEFINE_STRING(Ateml_rev, "Atmel rev:");
DEFINE_STRING(Broadcom_rev, "Broadcom rev:");
DEFINE_STRING(Qemu_TPM_rev, "Qemu TPM rev:");
DEFINE_STRING(IBM_TPM_rev, "IBM TPM rev:");
DEFINE_STRING(TPM_not_found, "TPM not found!");
DEFINE_STRING(TPM_unknown_ID, "TPM unknown! ID:");
DEFINE_STRING(access_register_not_valid, "access register not valid");
DEFINE_STRING(access_register_invalid, "access register invalid");
DEFINE_STRING(locality_already_active, "locality already active");
DEFINE_STRING(tis_write_not_ready, "tis_write() not ready");
DEFINE_STRING(tpm_expects_more_data, "TPM expects more data");
DEFINE_STRING(sts_not_valid, "sts not valid");
DEFINE_STRING(more_data_available, "more data available");
DEFINE_STRING(TIS_write_error, "  TIS write error:");
DEFINE_STRING(TIS_read_error, "  TIS read error:");
DEFINE_STRING(SABLE, "SABLE ");
DEFINE_STRING(n, "\n");
DEFINE_STRING(SABLE2, "SABLE:   ");
DEFINE_STRING(AMD_CPU_BOOTED_BY_SABLE, "AMD CPU booted by SABLE");
DEFINE_STRING(slbend_of_low, ".slb.end_of_low");
DEFINE_STRING(slbaligned_end_of_low, ".slb.aligned_end_of_low");
DEFINE_STRING(slbstart_of_high, ".slb.start_of_high");
DEFINE_STRING(slbend_of_high, ".slb.end_of_high");
DEFINE_STRING(TPM_Start_OSAP, "TPM_Start_OSAP()");
DEFINE_STRING(Erasing_srk_authdata, "\nErasing srk authdata from memory...\n");
DEFINE_STRING(TPM_Seal, "TPM_Seal()");
DEFINE_STRING(Erasing_passphrase_from_memory, "\nErasing passphrase from memory...\n");
DEFINE_STRING(Erasing_passphrase_authdata, "\nErasing passphrase authdata from memory...\n");
DEFINE_STRING(Erasing_owner_authdata,"\nErasing owner authdata from memory...\n");
DEFINE_STRING(TPM_NV_DefineSpace, "TPM_NV_DefineSpace()");
DEFINE_STRING(TPM_Start_OIAP,  "TPM_Start_OIAP()");
DEFINE_STRING(TPM_NV_WriteValueAuth, "TPM_NV_WriteValueAuth()");
DEFINE_STRING(TPM_NV_ReadValueAuth, "TPM_NV_ReadValueAuth()");
DEFINE_STRING(TPM_Unseal, "TPM_Unseal()");
DEFINE_STRING(Please_confirm_that_the_passphrase, "\nPlease confirm that the passphrase shown below matches the one which was entered during system configuration. If the passphrase does not match, contact your systems administrator immediately.\n\n");
DEFINE_STRING(Passphrase, "Passphrase: ");
DEFINE_STRING(If_this_is_correct, "\n\nIf this is correct, type 'yes' in all capitals: ");
DEFINE_STRING(YES, "YES");
DEFINE_STRING(module_flag_missing, "module flag missing");
DEFINE_STRING(no_module_to_hash, "no module to hash");
DEFINE_STRING(Hashing_modules_count, "Hashing modules count:");
DEFINE_STRING(config_magic_detected, "config magic detected");
DEFINE_STRING(Please_enter_the_passphrase, "Please enter the passphrase (64 char max): ");
DEFINE_STRING(mod_end_less_than_start, "mod_end less than start");
DEFINE_STRING(Module_starts_at, "Module starts at ");
DEFINE_STRING(Module_ends_at, "Module ends at ");
DEFINE_STRING(TPM_Extend, "TPM_Extend()");
DEFINE_STRING(tis_init_failed, "tis init failed");
DEFINE_STRING(could_not_gain_tis_ownership, "could not gain TIS ownership");
DEFINE_STRING(TPM_Startup_Clear, "TPM_Startup_Clear()");
DEFINE_STRING(tis_deactivate_failed, "tis_deactivate failed");
DEFINE_STRING(not_loaded_via_multiboot, "not loaded via multiboot");
DEFINE_STRING(No_SVM_platform, "No SVM platform");
DEFINE_STRING(Could_not_prepare_TPM ,"Could not prepare the TPM");
DEFINE_STRING(start_module_failed, "start module failed");
DEFINE_STRING(sending_an_INIT_IPI, "sending an INIT IPI to other processors failed");
DEFINE_STRING(call_skinit, "call skinit");
DEFINE_STRING(patch_CPU_name_tag, "patch CPU name tag");
DEFINE_STRING(cpu_name_to_long, "cpu name to long");
DEFINE_STRING(halt_APs_in_init_state, "halt APs in init state");
DEFINE_STRING(sending_an_STARTUP_IPI, "sending an STARTUP IPI to other processors failed");
DEFINE_STRING(SVM_revision,"SVM revision:");
DEFINE_STRING(enable_global_interrupt_flag, "enable global interrupt flag");
DEFINE_STRING(stgi, "stgi");
DEFINE_STRING(DEV_disable_failed, "DEV disable failed");
DEFINE_STRING(fixup_failed, "fixup failed");
DEFINE_STRING(fixup_done, "fixup done");
DEFINE_STRING(could_not_iterate_over_the_devices ,"could not iterate over the devices");
DEFINE_STRING(no_mbi_in_sable, "no mbi in sable()");
DEFINE_STRING(enter_srkAuthData, "Please enter the srkAuthData (20 char max): ");
DEFINE_STRING(enter_passPhraseAuthData, "Please enter the passPhraseAuthData (20 char max): ");
DEFINE_STRING(could_not_gain_TIS_ownership , "could not gain TIS ownership");
DEFINE_STRING(TPM_PcrRead, "TPM_PcrRead()");
DEFINE_STRING(PCR17, "PCR[17]: ");
DEFINE_STRING(calc_hash_failed, "calc hash failed");
DEFINE_STRING(PCR19, "PCR[19]: ");
DEFINE_STRING(Sealing_passPhrase, "\nSealing passphrase: \n\n");
DEFINE_STRING(to_PCR19_with_value, "\n\nto PCR[19] with value \n");
DEFINE_STRING(enter_ownerAuthData, "Please enter the ownerAuthData (20 char max): ");
DEFINE_STRING(Configuration_complete_Rebooting_now, "\nConfiguration complete. Rebooting now...\n");





















































