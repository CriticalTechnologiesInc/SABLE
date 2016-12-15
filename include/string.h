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

#endif
