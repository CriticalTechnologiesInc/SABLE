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
#include "string.h"

#define MSR_EFER 0xC0000080
#define EFER_SVME 1 << 12

#ifndef NDEBUG
#ifdef EXEC
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
#else
#define assert(X)
#endif

#define UNUSED(x) (void)(x)

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

#define TPM_WARNING(result, command_name)                                      \
  {                                                                            \
    if (result) {                                                              \
      out_string(s_WARNING);                                                   \
      out_string(command_name);                                                \
      out_string(s_dashes);                                                    \
      out_string(tpm_error_to_string(result));                                 \
      out_char('\n');                                                          \
    }                                                                          \
  }

#define TPM_ERROR(result, command_name)                                        \
  {                                                                            \
    if (result) {                                                              \
      out_string(s_ERROR);                                                     \
      out_string(command_name);                                                \
      out_string(s_dashes);                                                    \
      out_string(tpm_error_to_string(result));                                 \
      out_char('\n');                                                          \
      wait(10000);                                                             \
      reboot();                                                                \
    }                                                                          \
  }
/**
 * Returns result and prints the msg, if value is true.
 */
#define CHECK3(result, value, msg)                                             \
  {                                                                            \
    if (value) {                                                               \
      out_info(msg);                                                           \
      return result;                                                           \
    }                                                                          \
  }

/**
 * Returns result and prints the msg and hex, if value is true.
 */
#define CHECK4(result, value, msg, hex)                                        \
  {                                                                            \
    if (value) {                                                               \
      out_description(msg, hex);                                               \
      return result;                                                           \
    }                                                                          \
  }

/**
 * lowlevel helper functions
 */
UINT16 ntohs(UINT16 v);

/**
 * lowlevel output functions
 */
int out_char(unsigned value);
void out_unsigned(unsigned int value, int len, unsigned base, char flag);
void out_string(const char *value);
void hex_dump(unsigned char *bytestring, unsigned len);
void out_hex(unsigned int value, unsigned int bitlen);

/**
 * every message with out_description is prefixed with message_label
 */
extern const char const *message_label;
void out_description(const char *prefix, unsigned int value);
void out_info(const char *msg);

/**
 * Helper functions.
 */
void memcpy(void *dest, const void *src, UINT32 len);
void memset(void *s, BYTE c, UINT32 len);
UINT32 bufcmp(const void *buf1, const void *buf2, UINT32 size);
UINT32 nextln(BYTE **mptr, UINT32 mod_end);
UINT32 strnlen_sable(BYTE *value, UINT32 size);
void wait(int ms);
void exit(unsigned status) __attribute__((noreturn));
int check_cpuid(void);
int enable_svm(void);
void serial_init(void);
int keyboardReader(BYTE *entry, UINT32 BufSize);
