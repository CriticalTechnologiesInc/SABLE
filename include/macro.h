#ifndef ISABELLE
#define EXCLUDE(X) X
#else
#define EXCLUDE(X)
#endif

#define xstr(s) str(s)
#define str(s) #s

#ifndef NDEBUG
#define ASSERT(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      LOG("\nAssertion failed: '" xstr(X) "'\n\n");                            \
      dump_error();                                                            \
      exit(-1);                                                                \
    }                                                                          \
  }
#else
inline void assert(void) {}
#define ASSERT(X) assert();
#endif

#define UNUSED(x) (void)(x)

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
#define OPTION(Type) struct Type##_option
#else
#define OPTION(Type) OPTION_GEN(Type)
#endif
