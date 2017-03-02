/*++

There are platform dependent and general defines.

--*/

typedef unsigned char BYTE;
typedef signed char TSS_BOOL;
// basetsd.h provides definitions of UINT16, UINT32 and UINT64.
typedef unsigned short UINT16;
typedef unsigned long UINT32;
typedef unsigned long long UINT64;
typedef unsigned short TSS_UNICODE;
typedef void *PVOID;

typedef char bool;
#define true 1
#define false 0

#define NULL 0

#ifndef ISABELLE
#define EXCLUDE(X) X
#else
#define EXCLUDE(X)
#endif

#define xstr(s) str(s)
#define str(s) #s

/* Include this so that applications that use names as defined in the
 * 1.1 TSS specification can still compile
 */
//#include "compat11b.h"
