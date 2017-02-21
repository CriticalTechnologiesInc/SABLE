typedef enum tdERROR {
  NONE = 0,
  ERROR_BAD_ELF_HEADER,
  ERROR_SHA1_DATA_SIZE,
  ERROR_NO_MODULE,
  ERROR_AUTH_INTEGRITY,
  ERROR_TPM = 1 << 7,
} ERROR;

typedef struct tdEXCEPTION {
  ERROR error;
#ifndef NDEBUG
  const char *fileName;
  const char *lineNum;
  const char *msg;
#endif
} EXCEPTION;

typedef struct tdRESULT { EXCEPTION exception; } RESULT;

#ifndef NDEBUG
#define EXCEPT(exp, message)                                                   \
  ret.exception.error = exp;                                                   \
  ret.exception.fileName = __FILENAME__;                                       \
  ret.exception.lineNum = str(__LINE__);                                       \
  ret.exception.msg = message;
#else
#define EXCEPT(message)
#endif

/**
 * An exception 'error' is thrown when 'value' is true. In DEBUG mode,
 * 'msg' may be displayed if the error is caught. When 'value' is true,
 * 'ret' is returned to the caller.
 */
#define ERROR(value, error, msg)                                               \
  {                                                                            \
    if (value) {                                                               \
      EXCEPT(error, msg);                                                      \
      return ret;                                                              \
    }                                                                          \
  }

/**
 * An exception 'error' is thrown when 'value' is true. In DEBUG mode,
 * 'msg' may be displayed if the error is caught. When 'value' is true,
 * 'ret' is returned to the caller.
 */
#define TPM_ERROR(value, error, command_name)                                  \
  {                                                                            \
    if (value) {                                                               \
      EXCEPT(ERROR_TPM | error, xstr(command_name))                            \
      return ret;                                                              \
    }                                                                          \
  }

/**
 * Returns result and prints the msg, if value is true.
 */
#define CHECK3(result, value, msg)                                             \
  {                                                                            \
    if (value) {                                                               \
      EXCLUDE(out_string(msg);)                                                \
      return result;                                                           \
    }                                                                          \
  }

/**
 * Returns result and prints the msg and hex, if value is true.
 */
#define CHECK4(result, value, msg, hex)                                        \
  {                                                                            \
    if (value) {                                                               \
      EXCLUDE(out_description(msg, hex);)                                      \
      return result;                                                           \
    }                                                                          \
  }

/**
 * If the given EXCEPTION is an error, throw it (return it to the caller).
 */
#define THROW(e)                                                               \
  {                                                                            \
    if (e.error) {                                                             \
      ret.exception = e;                                                       \
      return ret;                                                              \
    }                                                                          \
  }

/**
 * If 'e' is any error, execute 'handler'
 */
#define CATCH_ANY(e, handler)                                                  \
  {                                                                            \
    if (e.error) {                                                             \
      handler;                                                                 \
    }                                                                          \
  }

/**
 * If 'e' is the error 'error', execute 'handler'
 */
#define CATCH(e, error, handler)                                               \
  {                                                                            \
    if (e.error == error) {                                                    \
      handler;                                                                 \
    }                                                                          \
  }
