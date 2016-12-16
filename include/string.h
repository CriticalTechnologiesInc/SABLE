#ifndef STRING_H
#define STRING_H

#define DECLARE_STRING(name) extern const char *const s_##name

DECLARE_STRING(no_capability_list_support);
DECLARE_STRING(SHA_data_exceeds_maximum_size);
DECLARE_STRING(exit);
DECLARE_STRING(reboot_now);
DECLARE_STRING(no_ext_cpuid);
DECLARE_STRING(no_SVM_support);
DECLARE_STRING(no_APIC_support);
DECLARE_STRING(could_not_enable_SVM);
DECLARE_STRING(pci_debug_format_string);
DECLARE_STRING(device_not_found);
DECLARE_STRING(cap_not_found);
DECLARE_STRING(invalid_DEV_HDR);
DECLARE_STRING(disable_DEV_and_SLDEV_protection);
DECLARE_STRING(DEV_not_found);
DECLARE_STRING(enable_dev_at);
DECLARE_STRING(enable_DEV_protection);
DECLARE_STRING(dev_pointer_invalid);
DECLARE_STRING(sldev_pointer_invalid);
DECLARE_STRING(not_BSP_or_APIC_disabled);
DECLARE_STRING(APIC_out_of_range);
DECLARE_STRING(Interrupt_pending);
DECLARE_STRING(No_module_to_start);
DECLARE_STRING(elf_magic);
DECLARE_STRING(elf_class_data);
DECLARE_STRING(ELF_header_incorrect);
DECLARE_STRING(ELF_type_incorrect);
DECLARE_STRING(e_phentsize_too_small);
DECLARE_STRING(jumping_to_next_segment);
DECLARE_STRING(address_d_not_aligned_or_larger_than_1MB);
DECLARE_STRING(configmagic);
DECLARE_STRING(WARNING);
DECLARE_STRING(dashes);
DECLARE_STRING(ERROR);
DECLARE_STRING(TPM_Start_OIAP_failed_on_transmit);
DECLARE_STRING(TPM_Unseal_failed_on_transmit);
DECLARE_STRING(secret_data_too_big_for_buffer);
DECLARE_STRING(could_not_get_random_number_from_TPM);
DECLARE_STRING(TPM_NV_DefineSpace_failed_on_transmit);
DECLARE_STRING(TPM_NV_ReadValueAuth_failed_on_transmit);
DECLARE_STRING(buffer_overflow_detected);
DECLARE_STRING(TPM_NV_WriteValueAuth_failed_on_transmit);
DECLARE_STRING(TPM_Flush_failed_on_transmit);
DECLARE_STRING(TPM_Seal_failed_on_transmit);
DECLARE_STRING(TPM_GetRandom_failed_on_transmit);
DECLARE_STRING(could_not_get_enough_random_bytes_from_TPM);
DECLARE_STRING(TPM_PcrRead_failed_on_transmit);
DECLARE_STRING(TPM_Extend_failed_on_transmit);
DECLARE_STRING(TPM_Start_OSAP_failed_on_transmit);
DECLARE_STRING(TPM_Startup_failed_on_transmit);
DECLARE_STRING(TPM_GetCapability_Pcrs_failed);
DECLARE_STRING(PCRs);
DECLARE_STRING(TPM_PcrRead_failed_with);
DECLARE_STRING(left_bracket);
DECLARE_STRING(right_bracket);

#endif
