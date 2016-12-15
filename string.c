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
#else
DEFINE_STRING(no_capability_list_support, 0);
DEFINE_STRING(SHA_data_exceeds_maximum_size, 0);
DEFINE_STRING(exit, 0);
DEFINE_STRING(reboot_now, 0);
DEFINE_STRING(no_ext_cpuid, 0);
DEFINE_STRING(no_SVM_support, 0);
DEFINE_STRING(no_APIC_support, 0);
DEFINE_STRING(could_not_enable_SVM, 0);
#endif
