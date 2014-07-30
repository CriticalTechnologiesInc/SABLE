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

extern const char string_literal;

#define MSR_EFER                       0xC0000080
#define EFER_SVME                      1<<12

#ifndef NDEBUG
#define assert(X) {if (!(X)) { out_string("\nAssertion failed: '" #X  "'\n\n"); exit(0xbadbbbad);}}
#else
#define assert(X)
#endif

#define UNUSED(x) (void)(x)

/**
 * we want inlined stringops
 */
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
	exit(result);						\
      }								\
  }

#else

#define ERROR(result, value, msg)				\
  {								\
    if (value)							\
      exit(result);						\
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
unsigned char kybrd_ctrl_read_status();

/**
 * lowlevel keyboard functions
 */
char key_stroke_listener();

typedef char bool;
#define true 1
#define false 0

enum KYBRD_ENCODER_IO {
    KYBRD_ENC_INPUT_BUF =   0x60,
    KYBRD_ENC_CMD_REG   =   0x60
};
 
enum KYBRD_CTRL_IO {
    KYBRD_CTRL_STATS_REG    =   0x64,
    KYBRD_CTRL_CMD_REG  =   0x64
};

enum KYBRD_CTRL_STATS_MASK {
 
    KYBRD_CTRL_STATS_MASK_OUT_BUF   =   0x01,      //00000001
    KYBRD_CTRL_STATS_MASK_IN_BUF    =   0x02,      //00000010
    KYBRD_CTRL_STATS_MASK_SYSTEM    =   0x04,      //00000100
    KYBRD_CTRL_STATS_MASK_CMD_DATA  =   0x08,      //00001000
    KYBRD_CTRL_STATS_MASK_LOCKED    =   0x10,       //00010000
    KYBRD_CTRL_STATS_MASK_AUX_BUF   =   0x20,       //00100000
    KYBRD_CTRL_STATS_MASK_TIMEOUT   =   0x40,       //01000000
    KYBRD_CTRL_STATS_MASK_PARITY    =   0x80        //10000000
};

enum KYBRD_ENC_CMDS {

	KYBRD_ENC_CMD_SET_LED				=	0xED,
	KYBRD_ENC_CMD_ECHO					=	0xEE,
	KYBRD_ENC_CMD_SCAN_CODE_SET			=	0xF0,
	KYBRD_ENC_CMD_ID					=	0xF2,
	KYBRD_ENC_CMD_AUTODELAY				=	0xF3,
	KYBRD_ENC_CMD_ENABLE				=	0xF4,
	KYBRD_ENC_CMD_RESETWAIT				=	0xF5,
	KYBRD_ENC_CMD_RESETSCAN				=	0xF6,
	KYBRD_ENC_CMD_ALL_AUTO				=	0xF7,
	KYBRD_ENC_CMD_ALL_MAKEBREAK			=	0xF8,
	KYBRD_ENC_CMD_ALL_MAKEONLY			=	0xF9,
	KYBRD_ENC_CMD_ALL_MAKEBREAK_AUTO	=	0xFA,
	KYBRD_ENC_CMD_SINGLE_AUTOREPEAT		=	0xFB,
	KYBRD_ENC_CMD_SINGLE_MAKEBREAK		=	0xFC,
	KYBRD_ENC_CMD_SINGLE_BREAKONLY		=	0xFD,
	KYBRD_ENC_CMD_RESEND				=	0xFE,
	KYBRD_ENC_CMD_RESET					=	0xFF
};

enum KEYCODE {

// Alphanumeric keys ////////////////

	KEY_SPACE             = ' ',
	KEY_0                 = '0',
	KEY_1                 = '1',
	KEY_2                 = '2',
	KEY_3                 = '3',
	KEY_4                 = '4',
	KEY_5                 = '5',
	KEY_6                 = '6',
	KEY_7                 = '7',
	KEY_8                 = '8',
	KEY_9                 = '9',

	KEY_A                 = 'a',
	KEY_B                 = 'b',
	KEY_C                 = 'c',
	KEY_D                 = 'd',
	KEY_E                 = 'e',
	KEY_F                 = 'f',
	KEY_G                 = 'g',
	KEY_H                 = 'h',
	KEY_I                 = 'i',
	KEY_J                 = 'j',
	KEY_K                 = 'k',
	KEY_L                 = 'l',
	KEY_M                 = 'm',
	KEY_N                 = 'n',
	KEY_O                 = 'o',
	KEY_P                 = 'p',
	KEY_Q                 = 'q',
	KEY_R                 = 'r',
	KEY_S                 = 's',
	KEY_T                 = 't',
	KEY_U                 = 'u',
	KEY_V                 = 'v',
	KEY_W                 = 'w',
	KEY_X                 = 'x',
	KEY_Y                 = 'y',
	KEY_Z                 = 'z',

	KEY_RETURN            = '\r',
	KEY_ESCAPE            = 0x1001,
	KEY_BACKSPACE         = '\b',

// Arrow keys ////////////////////////

	KEY_UP                = 0x1100,
	KEY_DOWN              = 0x1101,
	KEY_LEFT              = 0x1102,
	KEY_RIGHT             = 0x1103,

// Function keys /////////////////////

	KEY_F1                = 0x1201,
	KEY_F2                = 0x1202,
	KEY_F3                = 0x1203,
	KEY_F4                = 0x1204,
	KEY_F5                = 0x1205,
	KEY_F6                = 0x1206,
	KEY_F7                = 0x1207,
	KEY_F8                = 0x1208,
	KEY_F9                = 0x1209,
	KEY_F10               = 0x120a,
	KEY_F11               = 0x120b,
	KEY_F12               = 0x120b,
	KEY_F13               = 0x120c,
	KEY_F14               = 0x120d,
	KEY_F15               = 0x120e,

	KEY_DOT               = '.',
	KEY_COMMA             = ',',
	KEY_COLON             = ':',
	KEY_SEMICOLON         = ';',
	KEY_SLASH             = '/',
	KEY_BACKSLASH         = '\\',
	KEY_PLUS              = '+',
	KEY_MINUS             = '-',
	KEY_ASTERISK          = '*',
	KEY_EXCLAMATION       = '!',
	KEY_QUESTION          = '?',
	KEY_QUOTEDOUBLE       = '\"',
	KEY_QUOTE             = '\'',
	KEY_EQUAL             = '=',
	KEY_HASH              = '#',
	KEY_PERCENT           = '%',
	KEY_AMPERSAND         = '&',
	KEY_UNDERSCORE        = '_',
	KEY_LEFTPARENTHESIS   = '(',
	KEY_RIGHTPARENTHESIS  = ')',
	KEY_LEFTBRACKET       = '[',
	KEY_RIGHTBRACKET      = ']',
	KEY_LEFTCURL          = '{',
	KEY_RIGHTCURL         = '}',
	KEY_DOLLAR            = '$',
	KEY_POUND             = '#',
	KEY_EURO              = '$',
	KEY_LESS              = '<',
	KEY_GREATER           = '>',
	KEY_BAR               = '|',
	KEY_GRAVE             = '`',
	KEY_TILDE             = '~',
	KEY_AT                = '@',
	KEY_CARRET            = '^',

// Numeric keypad //////////////////////

	KEY_KP_0              = '0',
	KEY_KP_1              = '1',
	KEY_KP_2              = '2',
	KEY_KP_3              = '3',
	KEY_KP_4              = '4',
	KEY_KP_5              = '5',
	KEY_KP_6              = '6',
	KEY_KP_7              = '7',
	KEY_KP_8              = '8',
	KEY_KP_9              = '9',
	KEY_KP_PLUS           = '+',
	KEY_KP_MINUS          = '-',
	KEY_KP_DECIMAL        = '.',
	KEY_KP_DIVIDE         = '/',
	KEY_KP_ASTERISK       = '*',
	KEY_KP_NUMLOCK        = 0x300f,
	KEY_KP_ENTER          = 0x3010,

	KEY_TAB               = 0x4000,
	KEY_CAPSLOCK          = 0x4001,

// Modify keys ////////////////////////////

	KEY_LSHIFT            = 0x4002,
	KEY_LCTRL             = 0x4003,
	KEY_LALT              = 0x4004,
	KEY_LWIN              = 0x4005,
	KEY_RSHIFT            = 0x4006,
	KEY_RCTRL             = 0x4007,
	KEY_RALT              = 0x4008,
	KEY_RWIN              = 0x4009,

	KEY_INSERT            = 0x400a,
	KEY_DELETE            = 0x400b,
	KEY_HOME              = 0x400c,
	KEY_END               = 0x400d,
	KEY_PAGEUP            = 0x400e,
	KEY_PAGEDOWN          = 0x400f,
	KEY_SCROLLLOCK        = 0x4010,
	KEY_PAUSE             = 0x4011,

	KEY_UNKNOWN,
	KEY_NUMKEYCODES
};

#define isascii(c)	((unsigned)(c) <= 0x7F)

/**
 * every message with out_description is prefixed with message_label
 */
extern const char const * message_label;
void out_description(const char *prefix, unsigned int value);
void out_info(const char *msg);


/**
 * Helper functions.
 */
void memcpy(void *dest, const void *src, UINT32 len);
void memset(void *s, BYTE c, UINT32 len) ;
UINT32 bufcmp(BYTE *buf1, BYTE *buf2, UINT32 size);
UINT32 nextln(BYTE **mptr, UINT32 mod_end);
UINT32 strnlen_oslo(BYTE *value, UINT32 size);
void wait(int ms);
void exit(unsigned status) __attribute__((noreturn));
int check_cpuid(void);
int enable_svm(void);
void serial_init(void);
