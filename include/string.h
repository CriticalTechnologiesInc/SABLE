#ifndef STRING_H
#define STRING_H

#define DECLARE_STRING(str) extern const char *const s_ ## str

DECLARE_STRING(no_capability_list_support);
DECLARE_STRING(SHA_data_exceeds_maximum_size);

#endif
