#include "asm.h"
#include "amd.h"

/* EXCEPT:
 * ERROR_SVM_ENABLE
 *
 * Enables SVM support.
 */
RESULT enable_svm(void) {
  RESULT ret = {.exception.error = NONE};
  unsigned long long value;
  value = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, value | EFER_SVME);
  ERROR(!(rdmsr(MSR_EFER) & EFER_SVME), ERROR_SVM_ENABLE,
        "could not enable SVM");
  return ret;
}

/**
 * EXCEPT:
 * ERROR_NO_EXT
 * ERROR_NO_SVM
 * ERROR_NO_APIC
 *
 * Checks whether we have SVM support and a local APIC.
 *
 * @return: the SVM revision of the processor or a negative value, if
 * not supported.
 */
RESULT_(UINT32) check_cpuid(void) {
  RESULT_(UINT32) ret = {.exception.error = NONE};
  ERROR(0x8000000A > cpuid_eax(0x80000000), ERROR_NO_EXT, "no ext cpuid");
  ERROR(!(0x4 & cpuid_ecx(0x80000001)), ERROR_NO_SVM, "no SVM support");
  ERROR(!(0x200 & cpuid_edx(0x80000001)), ERROR_NO_APIC, "no APIC support");
  ret.value = cpuid_eax(0x8000000A) & 0xff;
  return ret;
}
