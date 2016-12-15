#include "string.h"

#define DEFINE_STRING(name, str) const char *const s_##name = str

#ifdef EXEC
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
DEFINE_STRING(disable_DEV_and_SLDEV_protection, "disable DEV and SLDEV protection");
DEFINE_STRING(DEV_not_found, "DEV not found");
DEFINE_STRING(enable_dev_at, "enable dev at");
DEFINE_STRING(enable_DEV_protection, "enable DEV protection");
DEFINE_STRING(dev_pointer_invalid, "dev pointer invalid");
DEFINE_STRING(sldev_pointer_invalid, "sldev pointer invalid");
DEFINE_STRING(not_BSP_or_APIC_disabled, "not BSP or APIC disabled");
DEFINE_STRING(APIC_out_of_range, "APIC out of range");
DEFINE_STRING(Interrupt_pending, "Interrupt pending");
#else
DEFINE_STRING(no_capability_list_support, 0);
DEFINE_STRING(SHA_data_exceeds_maximum_size, 0);
DEFINE_STRING(exit, 0);
DEFINE_STRING(reboot_now, 0);
DEFINE_STRING(no_ext_cpuid, 0);
DEFINE_STRING(no_SVM_support, 0);
DEFINE_STRING(no_APIC_support, 0);
DEFINE_STRING(could_not_enable_SVM, 0);
DEFINE_STRING(pci_debug_format_string, 0);
DEFINE_STRING(device_not_found, 0);
DEFINE_STRING(cap_not_found, 0);
DEFINE_STRING(invalid_DEV_HDR, 0);
DEFINE_STRING(disable_DEV_and_SLDEV_protection, 0);
DEFINE_STRING(DEV_not_found, 0);
DEFINE_STRING(enable_dev_at, 0);
DEFINE_STRING(enable_DEV_protection, 0);
DEFINE_STRING(dev_pointer_invalid, 0);
DEFINE_STRING(sldev_pointer_invalid, 0);
DEFINE_STRING(not_BSP_or_APIC_disabled, 0);
DEFINE_STRING(APIC_out_of_range, 0);
DEFINE_STRING(Interrupt_pending, 0);
#endif
