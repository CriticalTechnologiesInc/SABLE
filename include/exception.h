typedef enum tdERROR {
  NONE = 0,
  ERROR_BAD_ELF_HEADER,
  ERROR_SHA1_DATA_SIZE,
  ERROR_NO_MODULE,
  ERROR_BAD_MODULE,
  ERROR_BAD_TPM_VENDOR,
  ERROR_TIS_TRANSMIT,
  ERROR_TIS_LOCALITY_REGISTER_INVALID,
  ERROR_TIS_LOCALITY_ACCESS_TIMEOUT,
  ERROR_TIS_LOCALITY_ALREADY_ACCESSED,
  ERROR_PCI,
  ERROR_APIC,
  ERROR_DEV,
  ERROR_SVM_ENABLE,
  ERROR_NO_EXT,
  ERROR_NO_APIC,
  ERROR_NO_SVM,
  ERROR_BUFFER_OVERFLOW,
  ERROR_TPM_BAD_OUTPUT_PARAM,
  ERROR_TPM_BAD_OUTPUT_AUTH,
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

#define RESULT_GEN(Type)                                                       \
  struct Type##_exception {                                                    \
    EXCEPTION exception;                                                       \
    Type value;                                                                \
  }

/* This is a trick to force makeheaders to recognize EXCEPTION_GEN(Type) as
 * a dependency of EXCEPTION(Type) */
#ifndef BOGUS
#define RESULT(Type) struct Type##_exception
#else
#define RESULT(Type) RESULT_GEN(Type)
#endif

#ifndef NDEBUG
#define EXCEPT(exp, message)                                                   \
  ret.exception.error = exp;                                                   \
  ret.exception.fileName = __FILENAME__;                                       \
  ret.exception.lineNum = str(__LINE__);                                       \
  ret.exception.msg = message;
#else
#define EXCEPT(message) ret.exception.error = exp;
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
#define TPM_ERROR(error, command_name)                                         \
  {                                                                            \
    if (error) {                                                               \
      EXCEPT(ERROR_TPM | error, xstr(command_name))                            \
      return ret;                                                              \
    }                                                                          \
  }

/**
 * If 'e' is an exception, return it
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
