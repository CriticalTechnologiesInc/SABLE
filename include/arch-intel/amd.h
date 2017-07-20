#ifndef __AMD__
#define __AMD__

#include "platform.h"
#include "exception.h"

//#define MSR_EFER 0xC0000080
#define EFER_SVME 1 << 12

#ifndef RESULT_UINT32
#define RESULT_UINT32
RESULT_GEN(UINT32);
#endif

/**
 * EXCEPT:
 * ERROR_NO_EXT
 * ERROR_NO_SVM
 * ERROR_NO_APIC
 */
RESULT_(UINT32) check_cpuid(void);
/* EXCEPT: ERROR_SVM_ENABLE */
RESULT enable_svm(void);

#endif
