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
DEFINE_STRING(TPM_unknown!_ID, "TPM unknown! ID:");
DEFINE_STRING(access_register_not_valid, "access register not valid");
DEFINE_STRING(access_register_invalid, "access register invalid");
DEFINE_STRING(locality_already_active, "locality already active");
DEFINE_STRING(tis_write()_not_ready, "tis_write() not ready");
DEFINE_STRING(tpm_expects_more_data, "TPM expects more data");
DEFINE_STRING(sts_not_valid, "sts not valid");
DEFINE_STRING(more_data_available, "more data available");
DEFINE_STRING(TIS_write_error, "  TIS write error:");
DEFINE_STRING(TIS_read_error, "  TIS read error:");










