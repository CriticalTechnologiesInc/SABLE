typedef enum tdERROR {
  NONE = 0,
  ERROR_BAD_ELF_HEADER,
  ERROR_SHA1_DATA_SIZE,
  ERROR_NO_MODULE,
  ERROR_BAD_MODULE,
  ERROR_BAD_MBI,
  ERROR_NO_MBI,
  ERROR_BAD_TPM_VENDOR,
  ERROR_TIS_TRANSMIT,
  ERROR_TIS_LOCALITY_REGISTER_INVALID,
  ERROR_TIS_LOCALITY_ACCESS_TIMEOUT,
  ERROR_TIS_LOCALITY_ALREADY_ACCESSED,
  ERROR_TIS_LOCALITY_DEACTIVATE,
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

#ifndef NDEBUG
typedef struct {
  const char *file;
  const char *line;
  const char *function;
} SOURCE_LOCATION;

typedef struct SOURCE_LOCATION_LIST {
  SOURCE_LOCATION l;
  struct SOURCE_LOCATION_LIST *next;
} SOURCE_LOCATION_LIST;
#endif

typedef struct tdEXCEPTION {
  ERROR error;
#ifndef NDEBUG
  SOURCE_LOCATION_LIST *loc;
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
#define RESULT_(T) struct T##_exception
#else
#define RESULT_(T) RESULT_GEN(T)
#endif

#ifndef NDEBUG
#define EXCEPT(exp, message)                                                   \
  ret.exception.error = exp;                                                   \
  ret.exception.loc = alloc(sizeof(SOURCE_LOCATION_LIST));                     \
  ret.exception.loc->l.file = __FILENAME__;                                    \
  ret.exception.loc->l.line = xstr(__LINE__);                                  \
  ret.exception.loc->l.function = __func__;                                    \
  ret.exception.loc->next = NULL;                                              \
  ret.exception.msg = message;
#else
#define EXCEPT(exp, message) ret.exception.error = exp;
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

#ifndef NDEBUG
#define ERROR_TYPE(type, value, error, msg)                                    \
  {                                                                            \
    if (value) {                                                               \
      return (type){.exception.error = error,                                  \
                    .exception.loc = alloc(sizeof(SOURCE_LOCATION_LIST)),      \
                    .exception.loc->l.file = __FILENAME__,                     \
                    .exception.loc->l.line = xstr(__LINE__),                   \
                    .exception.loc->l.function = __func__,                     \
                    .exception.loc->next = NULL,                               \
                    .exception.msg = message};                                 \
    }                                                                          \
  }
#else
#define ERROR_TYPE(type, value, error, msg)                                    \
  {                                                                            \
    if (value) {                                                               \
      return (type){.exception.error = error};                                 \
    }                                                                          \
  }
#endif

/**
 * An exception 'error' is thrown when 'value' is true. In DEBUG mode,
 * 'msg' may be displayed if the error is caught. When 'value' is true,
 * 'ret' is returned to the caller.
 */
#define TPM_ERROR(error)                                                       \
  {                                                                            \
    if (error) {                                                               \
      EXCEPT(ERROR_TPM | error, tpm_error_to_string(error))                    \
      return ret;                                                              \
    }                                                                          \
  }

/**
 * If 'e' is an exception, return it
 */
#ifndef NDEBUG
#define THROW(e)                                                               \
  {                                                                            \
    if (e.error) {                                                             \
      ret.exception = e;                                                       \
      ret.exception.loc = alloc(sizeof(SOURCE_LOCATION_LIST));                 \
      ret.exception.loc->l.file = __FILENAME__;                                \
      ret.exception.loc->l.line = xstr(__LINE__);                              \
      ret.exception.loc->l.function = __func__;                                \
      ret.exception.loc->next = e.loc;                                         \
      return ret;                                                              \
    }                                                                          \
  }
#else
#define THROW(e)                                                               \
  {                                                                            \
    if (e.error) {                                                             \
      ret.exception = e;                                                       \
      return ret;                                                              \
    }                                                                          \
  }
#endif

#ifndef NDEBUG
#define THROW_TYPE(type, e)                                                    \
  {                                                                            \
    if (e.error) {                                                             \
      return (type){.exception.error = e,                                      \
                    .exception.loc = alloc(sizeof(SOURCE_LOCATION_LIST)),      \
                    .exception.loc->l.file = __FILENAME__,                     \
                    .exception.loc->l.line = xstr(__LINE__),                   \
                    .exception.loc->l.function = __func__,                     \
                    .exception.loc->next = e.loc};                             \
    }                                                                          \
  }
#else
#define THROW_TYPE(type, e)                                                    \
  {                                                                            \
    if (e.error) {                                                             \
      return (type){.exception = e};                                           \
    }                                                                          \
  }
#endif

/**
 * If 'e' is any error, execute 'handler'
 */
#define CATCH_ANY(e, handler)                                                  \
  {                                                                            \
    if (e.error) {                                                             \
      { handler; };                                                            \
      e.error = NONE;                                                          \
    }                                                                          \
  }

/**
 * If 'e' is the error 'error', execute 'handler'
 */
#define CATCH(e, ex, handler)                                                  \
  {                                                                            \
    if (e.error == (ex)) {                                                     \
      { handler; };                                                            \
      e.error = NONE;                                                          \
    }                                                                          \
  }
