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

#endif
