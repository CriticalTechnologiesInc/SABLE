#include "string.h"

#define DEFINE_STRING(name, str) const char *const s_ ## name = str

#ifdef EXEC
DEFINE_STRING(no_capability_list_support, "no capability list support");
DEFINE_STRING(SHA_data_exceeds_maximum_size, "SHA data exceeds maximum size");
#else
DEFINE_STRING(no_capability_list_support, 0);
DEFINE_STRING(SHA_data_exceeds_maximum_size, 0);
#endif
