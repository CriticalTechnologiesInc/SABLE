#ifndef OPTION_H
#define OPTION_H

#define OPTION_GEN(Type) \
  typedef struct { \
    TSS_BOOL has_value; \
    Type value; \
  } OPTION_##Type;

#define OPTION(Type) OPTION_##Type

#endif
