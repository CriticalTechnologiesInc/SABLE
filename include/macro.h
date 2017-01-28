#ifndef ISABELLE
#define EXCLUDE(X) X
#else
#define EXCLUDE(X)
#endif

#define xstr(s) str(s)
#define str(s) #s

#ifndef ISABELLE
#define assert(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      out_string("\nAssertion failed: '" #X "'\n\n");                          \
      exit(0xbadbbbad);                                                        \
    }                                                                          \
  }
#else
#define assert(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      exit(0xbadbbbad);                                                        \
    }                                                                          \
  }
#endif

#define UNUSED(x) (void)(x)

#ifndef ISABELLE
#ifndef NDEBUG
/**
 * A fatal error happens if value is true.
 */
#define ERROR(result, value, msg)                                              \
  {                                                                            \
    if (value) {                                                               \
      out_string(msg);                                                         \
      exit(result);                                                            \
    }                                                                          \
  }
#else
#define ERROR(result, value, msg)                                              \
  {                                                                            \
    if (value)                                                                 \
      exit(result);                                                            \
  }
#endif
#else
#define ERROR(result, value, msg)                                              \
  {                                                                            \
    if (value)                                                                 \
      exit(result);                                                            \
  }
#endif

#ifndef ISABELLE
#define TPM_WARNING(result, command_name)                                      \
  {                                                                            \
    if (result) {                                                              \
      out_string("\nWARNING: ");                                                   \
      out_string(command_name);                                                \
      out_string(" -- ");                                                    \
      out_string(tpm_error_to_string(result));                                 \
      out_char('\n');                                                          \
    }                                                                          \
  }
#else
#define TPM_WARNING(result, command_name) // Nothing
#endif

#ifndef ISABELLE
#define TPM_ERROR(result, command_name)                                        \
  {                                                                            \
    if (result) {                                                              \
      out_string("\nERROR: ");                                                     \
      out_string(command_name);                                                \
      out_string(" -- ");                                                    \
      out_string(tpm_error_to_string(result));                                 \
      out_char('\n');                                                          \
      wait(10000);                                                             \
      reboot();                                                                \
    }                                                                          \
  }
#else
#define TPM_ERROR(result, command_name)                                        \
  {                                                                            \
    if (result) {                                                              \
      exit(result);                                                            \
    }                                                                          \
  }
#endif

/**
 * Returns result and prints the msg, if value is true.
 */
#ifndef ISABELLE
#define CHECK3(result, value, msg)                                             \
  {                                                                            \
    if (value) {                                                               \
      out_info(msg);                                                           \
      return result;                                                           \
    }                                                                          \
  }
#else
#define CHECK3(result, value, msg)                                             \
  {                                                                            \
    if (value) {                                                               \
      return result;                                                           \
    }                                                                          \
  }
#endif

/**
 * Returns result and prints the msg and hex, if value is true.
 */
#ifndef ISABELLE
#define CHECK4(result, value, msg, hex)                                        \
  {                                                                            \
    if (value) {                                                               \
      out_description(msg, hex);                                               \
      return result;                                                           \
    }                                                                          \
  }
#else
#define CHECK4(result, value, msg, hex)                                        \
  {                                                                            \
    if (value) {                                                               \
      return result;                                                           \
    }                                                                          \
  }
#endif
