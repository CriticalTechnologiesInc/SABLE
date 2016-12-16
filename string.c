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
