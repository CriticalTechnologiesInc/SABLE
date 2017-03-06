#ifndef __OPTION_H__
#define __OPTION_H__

/* TYPE GENERATORS */

/* Convention: when generating an OPTION for "Type", #define a preprocessor
 * symbol OPTION_Type, which can be used by other code to detect whether the
 * given
 * type has already been generated. Example usage:
 *
 * #ifndef OPTION_int
 * #define OPTION_int
 * OPTION_GEN(int)
 * #endif
 *
 * This is analogous to the common convention for guarding C header files.
 */
#define OPTION_GEN(Type)                                                       \
  struct Type##_option {                                                       \
    Type value;                                                                \
    char hasValue;                                                             \
  }

/* This is a trick to force makeheaders to recognize OPTION_GEN(Type) as
 * a dependency of OPTION(Type) */
#ifndef BOGUS
#define OPTION(T) struct T##_option
#else
#define OPTION(T) OPTION_GEN(T)
#endif

#endif
