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

#endif
