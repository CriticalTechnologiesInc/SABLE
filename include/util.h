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

#define NULL 0

#define MSR_EFER 0xC0000080
#define EFER_SVME 1 << 12

RESULT_GEN(UINT32);

/**
 * Swaps bytes in a short, like ntohl()
 */
static inline UINT16 ntohs(UINT16 v) { return (v >> 8) | (v << 8); }
static inline UINT16 htons(UINT16 v) { return (v >> 8) | (v << 8); }

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
void out_description(const char *prefix, unsigned int value);
void out_info(const char *msg);

/**
 * Helper functions.
 */
void do_xor(const BYTE *in1, const BYTE *in2, BYTE *out, UINT32 size);
void pad(BYTE *in, BYTE val, BYTE insize, BYTE outsize);
void *memcpy(void *dest, const void *src, UINT32 len);
char *strncpy(char *dest, const char *src, UINT32 num);
UINT32 strlen(const char *str);
void memset(void *s, BYTE c, UINT32 len);
UINT32 memcmp(const void *buf1, const void *buf2, UINT32 size);
UINT32 nextln(BYTE **mptr, UINT32 mod_end);
void wait(int ms);
void dump_exception(EXCEPTION e);
void exit(unsigned status) __attribute__((noreturn));
/**
 * EXCEPT:
 * ERROR_NO_EXT
 * ERROR_NO_SVM
 * ERROR_NO_APIC
 */
RESULT_(UINT32) check_cpuid(void);
/* EXCEPT: ERROR_SVM_ENABLE */
RESULT enable_svm(void);
void show_hash(const char *s, TPM_DIGEST hash);
