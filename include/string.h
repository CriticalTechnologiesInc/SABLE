#ifndef STRING_H
#define STRING_H

#define DECLARE_STRING(name) extern const char *const s_##name
#define AUTHDATA_STR_SIZE 64
#define PASSPHRASE_STR_SIZE 128

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
DECLARE_STRING(Fix_DID_VID_bug);
DECLARE_STRING(STM_rev);
DECLARE_STRING(Infineon_rev);
DECLARE_STRING(Ateml_rev);
DECLARE_STRING(Broadcom_rev);
DECLARE_STRING(Qemu_TPM_rev);
DECLARE_STRING(IBM_TPM_rev);
DECLARE_STRING(TPM_not_found);
DECLARE_STRING(TPM_unknown_ID);
DECLARE_STRING(access_register_not_valid);
DECLARE_STRING(access_register_invalid);
DECLARE_STRING(locality_already_active);
DECLARE_STRING(tis_write_not_ready);
DECLARE_STRING(tpm_expects_more_data);
DECLARE_STRING(sts_not_valid);
DECLARE_STRING(more_data_available);
DECLARE_STRING(TIS_write_error);
DECLARE_STRING(TIS_read_error);
DECLARE_STRING(SABLE);
DECLARE_STRING(n);
DECLARE_STRING(SABLE2);
DECLARE_STRING(AMD_CPU_BOOTED_BY_SABLE);
DECLARE_STRING(slbend_of_low);
DECLARE_STRING(slbaligned_end_of_low);
DECLARE_STRING(slbstart_of_high);
DECLARE_STRING(slbend_of_high);
DECLARE_STRING(TPM_Start_OSAP);
DECLARE_STRING(Erasing_srk_authdata);
DECLARE_STRING(TPM_Seal);
DECLARE_STRING(Erasing_passphrase_from_memory);
DECLARE_STRING(Erasing_passphrase_authdata);
DECLARE_STRING(Erasing_nv_authdata);
DECLARE_STRING(TPM_NV_DefineSpace);
DECLARE_STRING(TPM_Start_OIAP);
DECLARE_STRING(TPM_NV_WriteValueAuth);
DECLARE_STRING(TPM_NV_ReadValueAuth);
DECLARE_STRING(TPM_Unseal);
DECLARE_STRING(Please_confirm_that_the_passphrase);
DECLARE_STRING(Passphrase);
DECLARE_STRING(If_this_is_correct);
DECLARE_STRING(YES);
DECLARE_STRING(module_flag_missing);
DECLARE_STRING(no_module_to_hash);
DECLARE_STRING(Hashing_modules_count);
DECLARE_STRING(config_magic_detected);
DECLARE_STRING(Please_enter_the_passphrase);
DECLARE_STRING(mod_end_less_than_start);
DECLARE_STRING(Module_starts_at);
DECLARE_STRING(Module_ends_at);
DECLARE_STRING(TPM_Extend);
DECLARE_STRING(tis_init_failed);
DECLARE_STRING(could_not_gain_tis_ownership);
DECLARE_STRING(TPM_Startup_Clear);
DECLARE_STRING(tis_deactivate_failed);
DECLARE_STRING(not_loaded_via_multiboot);
DECLARE_STRING(No_SVM_platform);
DECLARE_STRING(Could_not_prepare_TPM);
DECLARE_STRING(start_module_failed);
DECLARE_STRING(could_not_enable_SVM);
DECLARE_STRING(sending_an_INIT_IPI);
DECLARE_STRING(call_skinit);
DECLARE_STRING(patch_CPU_name_tag);
DECLARE_STRING(cpu_name_to_long);
DECLARE_STRING(halt_APs_in_init_state);
DECLARE_STRING(sending_an_STARTUP_IPI);
DECLARE_STRING(could_not_enable_SVM);
DECLARE_STRING(SVM_revision);
DECLARE_STRING(enable_global_interrupt_flag);
DECLARE_STRING(stgi);
DECLARE_STRING(DEV_disable_failed);
DECLARE_STRING(fixup_failed);
DECLARE_STRING(nonce_generation_failed);
DECLARE_STRING(fixup_done);
DECLARE_STRING(could_not_iterate_over_the_devices);
DECLARE_STRING(no_mbi_in_sable);
DECLARE_STRING(enter_srkAuthData);
DECLARE_STRING(enter_passPhraseAuthData);
DECLARE_STRING(could_not_gain_TIS_ownership);
DECLARE_STRING(TPM_PcrRead);
DECLARE_STRING(PCR17);
DECLARE_STRING(calc_hash_failed);
DECLARE_STRING(PCR19);
DECLARE_STRING(Sealing_passPhrase);
DECLARE_STRING(to_PCR19_with_value);
DECLARE_STRING(enter_nvAuthData);
DECLARE_STRING(tis_deactivate_failed);
DECLARE_STRING(Configuration_complete_Rebooting_now);
DECLARE_STRING(start_module_failed);
DECLARE_STRING(version_string);
DECLARE_STRING(message_label);
DECLARE_STRING(CPU_NAME);

#endif
