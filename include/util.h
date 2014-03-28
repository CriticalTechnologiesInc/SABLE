/*
 * \brief   utility macros and headers for util.c
 * \date    2006-03-28
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */

#pragma once

#include "asm.h"
#include "platform.h"


#define MSR_EFER                       0xC0000080
#define EFER_SVME                      1<<12

#ifndef NDEBUG
#define assert(X) {if (!(X)) { out_string("\nAssertion failed: '" #X  "'\n\n"); __exit(0xbadbbbad);}}
#else
#define assert(X)
#endif

#define UNUSED(x) (void)(x)

/**
 * we want inlined stringops
 */
#define memcpy(x,y,z) __builtin_memcpy(x,y,z)
#define memset(x,y,z) __builtin_memset(x,y,z)
#define strlen(x)     __builtin_strlen(x)

#ifndef NDEBUG

/**
 * A fatal error happens if value is true.
 */
#define ERROR(result, value, msg)				\
  {								\
    if (value)							\
      {								\
	out_string(msg);					\
	__exit(result);						\
      }								\
  }

#else

#define ERROR(result, value, msg)				\
  {								\
    if (value)							\
      __exit(result);						\
  }
#endif

/**
 * Returns result and prints the msg, if value is true.
 */
#define CHECK3(result, value, msg)			\
  {							\
    if (value)						\
      {							\
	out_info(msg);					\
	return result;					\
      }							\
  }

/**
 * Returns result and prints the msg and hex, if value is true.
 */
#define CHECK4(result, value, msg, hex)			\
  {							\
    if (value)						\
      {							\
	out_description(msg, hex);			\
	return result;					\
      }							\
  }

/**
 * For use whenever checking the return value on a TPM command
 */
#define CHECK_TPM(result, value, msg, hex)			\
  {							\
    if (value)						\
      {							\
	out_description(msg, hex);			\
	return result;					\
      }							\
  }


/**
 * lowlevel helper functions
 */
UINT16 ntohs(UINT16 v);

/**
 * lowlevel output functions
 */
int  out_char(unsigned value);
void out_unsigned(unsigned int value, int len, unsigned base, char flag);
void out_string(const char *value);
void hex_dump(unsigned char *bytestring, unsigned len);
void out_hex(unsigned int value, unsigned int bitlen);

/**
 * every message with out_description is prefixed with message_label
 */
extern const char const * message_label;
void out_description(const char *prefix, unsigned int value);
void out_info(const char *msg);


/**
 * Helper functions.
 */
UINT32 bufcmp(BYTE *buf1, BYTE *buf2, UINT32 size);
UINT32 nextln(BYTE **mptr, UINT32 mod_end);
UINT32 strnlen_oslo(BYTE *value, UINT32 size);
void wait(int ms);
void __exit(unsigned status) __attribute__((noreturn));
int check_cpuid(void);
int enable_svm(void);
void serial_init(void);
