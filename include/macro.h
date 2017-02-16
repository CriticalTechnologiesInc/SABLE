#ifndef ISABELLE
#define EXCLUDE(X) X
#else
#define EXCLUDE(X)
#endif

#define xstr(s) str(s)
#define str(s) #s

#ifndef NDEBUG
void log(const char *file, const char *line, const char *message);
#define LOG(message) log(__FILENAME__, xstr(__LINE__), message)
void log_tpm(const char *file, const char *line, const char *cmd,
             const char *message);
#define LOG_TPM(cmd, message)                                                  \
  log_tpm(__FILENAME__, xstr(__LINE__), str(cmd), message)
void log_desc(const char *file, const char *line, const char *message,
              unsigned hex);
#define LOG_DESC(message, val)                                                 \
  log_desc(__FILENAME__, xstr(__LINE__), message, val)
#else
#define LOG(message)
#define LOG_TPM(cmd, message)
#endif

#define assert(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      LOG("\nAssertion failed: '" xstr(X) "'\n\n");                            \
      exit();                                                        \
    }                                                                          \
  }

#define UNUSED(x) (void)(x)

/**
 * A fatal error happens if value is true.
 */
#define ERROR(result, value, msg)                                              \
  {                                                                            \
    if (value) {                                                               \
      LOG(msg);                                                                \
      EXCLUDE(out_description("\nexit()", result);)                            \
      exit();                                                                  \
    }                                                                          \
  }

#define TPM_ERROR(result, command_name)                                        \
  {                                                                            \
    if (result) {                                                              \
      LOG_TPM(command_name, tpm_error_to_string(result));                      \
      EXCLUDE(wait(10000);)                                                    \
      exit();                                                                  \
    }                                                                          \
  }

/**
 * Returns result and prints the msg, if value is true.
 */
#define CHECK3(result, value, msg)                                             \
  {                                                                            \
    if (value) {                                                               \
      LOG(msg);                                                                \
      return result;                                                           \
    }                                                                          \
  }

/**
 * Returns result and prints the msg and hex, if value is true.
 */
#define CHECK4(result, value, msg, hex)                                        \
  {                                                                            \
    if (value) {                                                               \
      LOG_DESC(msg, hex);                                                      \
      return result;                                                           \
    }                                                                          \
  }

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
