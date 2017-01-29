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
#define LOG_DESC(message, val) log_desc(__FILENAME__, xstr(__LINE__), message, val)
#else
#define LOG(message)
#define LOG_TPM(cmd, message)
#endif

#define assert(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      LOG("\nAssertion failed: '" xstr(X) "'\n\n");                            \
      exit(0xbadbbbad);                                                        \
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
      exit(result);                                                            \
    }                                                                          \
  }

#define TPM_ERROR(result, command_name)                                        \
  {                                                                            \
    if (result) {                                                              \
      LOG_TPM(command_name, tpm_error_to_string(result));                      \
      EXCLUDE(wait(10000);)                                                    \
      exit(result);                                                            \
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
