/*
 * \brief   Utility functions for a bootloader
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


#include "include/util.h"

const char string_literal = 0;

void
memcpy(void *dest, const void *src, UINT32 len) 
{
    BYTE *dp = dest;
    const BYTE *sp = src;
    for (UINT32 i = 0; i < len; i++)
    {
        *dp = *sp;
        dp++;
        sp++;
    }
}

void
memset(void *s, BYTE c, UINT32 len) 
{
    BYTE *p = s;
    for (UINT32 i = 0; i < len; i++)
    {
        *p = c;
        p++;
    }
}

/**
 * Swaps bytes in a short, like ntohl()
 */
UINT16
ntohs(UINT16 v)
{
  return (v>>8) | (v<<8);
}

// like strlen
UINT32
strnlen_oslo(BYTE *value, UINT32 size)
{
    unsigned long i;
    for(i = 0; i < size; i++)
        if(*(value + i) == 0)
            break;
    return i;
}

//compares two buffers for a certain length
UINT32
bufcmp(BYTE *buf1, BYTE *buf2, UINT32 size)
{
    UINT32 i;
    for(i = 0; i < size; i++)
        if(*(buf1+ i) != *(buf2+i))
            break;
    return (i<size);
}

//make mptr point to the next line in an ascii module.
//return the amount of bytes in the current line.
//return -1 if mptr goes off the boundary 
UINT32 
nextln(BYTE **mptr, UINT32 mod_end){
    UINT32 i=0;
    while(**mptr!=0x0a)
    {
        if((UINT32) *mptr > mod_end)
            return -1;
        i++;
        (*mptr)++;
    }
    (*mptr)++;
    return i;
}



/**
 * Wait roughly a given number of milliseconds.
 *
 * We use the PIT for this.
 */
void
wait(int ms)
{
  /* the PIT counts with 1.193 Mhz */
  ms*=1193;

  /* initalize the PIT, let counter0 count from 256 backwards */
  outb(0x43, 0x34);
  outb(0x40, 0);
  outb(0x40, 0);

  unsigned short state;
  unsigned short old = 0;
  while (ms>0)
    {
      outb(0x43, 0);
      state = inb(0x40);
      state |= inb(0x40) << 8;
      ms -= (unsigned short)(old - state);
      old = state;
    }
}

/**
 * Print the exit status and reboot the machine.
 */
void
exit(unsigned status)
{
  out_char('\n');
  //out_description("exit()", status);
  out_description(&string_literal, status);
  for (unsigned i=0; i<1000;i++)
    {
      wait(1000);
      //out_char('.');
    }
  //out_string("-> OK, reboot now!\n");
  out_string(&string_literal);
  reboot();
}

/**
 * Checks whether we have SVM support and a local APIC.
 *
 * @return: the SVM revision of the processor or a negative value, if
 * not supported.
 */
int
check_cpuid()
{
  int res;
  //CHECK3(-31,0x8000000A > cpuid_eax(0x80000000), "no ext cpuid");
  CHECK3(-31,0x8000000A > cpuid_eax(0x80000000), &string_literal);
  //CHECK3(-32,!(0x4   & cpuid_ecx(0x80000001)), "no SVM support");
  CHECK3(-32,!(0x4   & cpuid_ecx(0x80000001)), &string_literal);
  //CHECK3(-33,!(0x200 & cpuid_edx(0x80000001)), "no APIC support");
  CHECK3(-33,!(0x200 & cpuid_edx(0x80000001)), &string_literal);
  res = cpuid_eax(0x8000000A) & 0xff;
  return res;
}


/**
 * Enables SVM support.
 *
 */
int
enable_svm()
{
  unsigned long long value;
  value = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, value | EFER_SVME);
  //CHECK3(-40, !(rdmsr(MSR_EFER) & EFER_SVME), "could not enable SVM");
  CHECK3(-40, !(rdmsr(MSR_EFER) & EFER_SVME), &string_literal);
  return 0;
}

/**
 * Output a single char.
 * Note: We allow only to put a char on the last line.
 */
int
out_char(unsigned value)
{
#define BASE(ROW) ((unsigned short *) (0xb8000+ROW*160))
  static unsigned int col;
  if (value!='\n')
    {
      unsigned short *p = BASE(24)+col;
      *p = 0x0f00 | value;
      col++;
    }

  if (col>=80 || value == '\n')
    {
      col=0;
      unsigned short *p=BASE(0);
      memcpy(p, p+80, 24*160);
      memset(BASE(24), 0, 160);
    }

  return value;
}

/**
 * Output a string.
 */
void
out_string(const char *value)
{
  for(; *value; value++)
    out_char(*value);
}

/**
 * Output many hex values
 */
void
hex_dump(unsigned char *bytestring, unsigned len)
{
    for(unsigned i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            out_char('\n');
        else if (i % 4 == 0)
            out_char(' ');
        out_hex(*(bytestring+i), 7);
    }
    out_char('\n');
}

/**
 * Output a single hex value.
 */
void
out_hex(unsigned value, unsigned bitlen)
{
  int i;
  for (i=bsr(value | 1<<bitlen) &0xfc; i>=0; i-=4)
    {
      unsigned a = (value >> i) & 0xf;
      if (a>=10)
	a += 7;
      a+=0x30;

      out_char(a);
    }
}

/**
 * Output a string followed by a single hex value, prefixed with a
 * message label.
 */
void
out_description(const char *prefix, unsigned int value)
{
  out_string(message_label);
  out_string(prefix);
  out_char(' ');
  out_hex(value, 0);
  out_char('\n');
}

/**
 * Output a string, prefixed with a message label.
 */
void
out_info(const char *msg)
{
  out_string(message_label);
  out_string(msg);
  out_char('\n');
}

/***************************************************************
 * Keyboard Input
 ***************************************************************/
static int scancode;
static bool shift, capslock;

static int kkybrd_scancode_std [] = {

	//! key			scancode
	KEY_UNKNOWN,	//0
	KEY_ESCAPE,		//1
	KEY_1,			//2
	KEY_2,			//3
	KEY_3,			//4
	KEY_4,			//5
	KEY_5,			//6
	KEY_6,			//7
	KEY_7,			//8
	KEY_8,			//9
	KEY_9,			//0xa
	KEY_0,			//0xb
	KEY_MINUS,		//0xc
	KEY_EQUAL,		//0xd
	KEY_BACKSPACE,	//0xe
	KEY_TAB,		//0xf
	KEY_Q,			//0x10
	KEY_W,			//0x11
	KEY_E,			//0x12
	KEY_R,			//0x13
	KEY_T,			//0x14
	KEY_Y,			//0x15
	KEY_U,			//0x16
	KEY_I,			//0x17
	KEY_O,			//0x18
	KEY_P,			//0x19
	KEY_LEFTBRACKET,//0x1a
	KEY_RIGHTBRACKET,//0x1b
	KEY_RETURN,		//0x1c
	KEY_LCTRL,		//0x1d
	KEY_A,			//0x1e
	KEY_S,			//0x1f
	KEY_D,			//0x20
	KEY_F,			//0x21
	KEY_G,			//0x22
	KEY_H,			//0x23
	KEY_J,			//0x24
	KEY_K,			//0x25
	KEY_L,			//0x26
	KEY_SEMICOLON,	//0x27
	KEY_QUOTE,		//0x28
	KEY_GRAVE,		//0x29
	KEY_LSHIFT,		//0x2a
	KEY_BACKSLASH,	//0x2b
	KEY_Z,			//0x2c
	KEY_X,			//0x2d
	KEY_C,			//0x2e
	KEY_V,			//0x2f
	KEY_B,			//0x30
	KEY_N,			//0x31
	KEY_M,			//0x32
	KEY_COMMA,		//0x33
	KEY_DOT,		//0x34
	KEY_SLASH,		//0x35
	KEY_RSHIFT,		//0x36
	KEY_KP_ASTERISK,//0x37
	KEY_RALT,		//0x38
	KEY_SPACE,		//0x39
	KEY_CAPSLOCK,	//0x3a
	KEY_F1,			//0x3b
	KEY_F2,			//0x3c
	KEY_F3,			//0x3d
	KEY_F4,			//0x3e
	KEY_F5,			//0x3f
	KEY_F6,			//0x40
	KEY_F7,			//0x41
	KEY_F8,			//0x42
	KEY_F9,			//0x43
	KEY_F10,		//0x44
	KEY_KP_NUMLOCK,	//0x45
	KEY_SCROLLLOCK,	//0x46
	KEY_HOME,		//0x47
	KEY_KP_8,		//0x48	//keypad up arrow
	KEY_PAGEUP,		//0x49
	KEY_KP_2,		//0x50	//keypad down arrow
	KEY_KP_3,		//0x51	//keypad page down
	KEY_KP_0,		//0x52	//keypad insert key
	KEY_KP_DECIMAL,	//0x53	//keypad delete key
	KEY_UNKNOWN,	//0x54
	KEY_UNKNOWN,	//0x55
	KEY_UNKNOWN,	//0x56
	KEY_F11,		//0x57
	KEY_F12			//0x58
};

//! invalid scan code. Used to indicate the last scan code is not to be reused
const int INVALID_SCANCODE = 0;

//! read status from keyboard controller
unsigned char kybrd_ctrl_read_status() {
    return inb(KYBRD_CTRL_STATS_REG);
}

//! send command byte to keyboard controller
void kybrd_ctrl_send_cmd(BYTE cmd) {
 
    //! wait for kkybrd controller input buffer to be clear
    while (1)
        if ( (kybrd_ctrl_read_status () & KYBRD_CTRL_STATS_MASK_IN_BUF) == 0)
            break;
 
    outb(KYBRD_CTRL_CMD_REG, cmd);
}

//! read keyboard encoder buffer
BYTE kybrd_enc_read_buf () {
    return inb(KYBRD_ENC_INPUT_BUF);
}
 
//! send command byte to keyboard encoder
void kybrd_enc_send_cmd (BYTE cmd) {
 
    //! wait for kkybrd controller input buffer to be clear
    while (!((kybrd_ctrl_read_status () & KYBRD_CTRL_STATS_MASK_IN_BUF) == 0)) {}
 
    //! send command byte to kybrd encoder
    outb(KYBRD_ENC_CMD_REG, cmd);
}

//! sets leds
void kkybrd_set_leds (bool num, bool caps, bool scroll) {

	BYTE data = 0;

	//! set or clear the bit
	data = (scroll) ? (data | 1) : (data & 1);
	data = (num) ? (num | 2) : (num & 2);
	data = (caps) ? (num | 4) : (num & 4);

	//! send the command -- update keyboard Light Emetting Diods (LEDs)
	kybrd_enc_send_cmd (KYBRD_ENC_CMD_SET_LED);
	kybrd_enc_send_cmd (data);
}

//! convert key to an ascii character
char kybrd_key_to_ascii (int code) {

	BYTE key = code;

	//! insure key is an ascii character
	if (isascii (key)) {

		//! if shift key is down or caps lock is on, make the key uppercase
		if (shift || capslock)
			if (key >= 'a' && key <= 'z')
				key -= 32;

		if (shift && !capslock)
        {
			if (key >= '0' && key <= '9')
            {
				switch (key) {

					case '0':
						key = KEY_RIGHTPARENTHESIS;
						break;
					case '1':
						key = KEY_EXCLAMATION;
						break;
					case '2':
						key = KEY_AT;
						break;
					case '3':
						key = KEY_EXCLAMATION;
						break;
					case '4':
						key = KEY_HASH;
						break;
					case '5':
						key = KEY_PERCENT;
						break;
					case '6':
						key = KEY_CARRET;
						break;
					case '7':
						key = KEY_AMPERSAND;
						break;
					case '8':
						key = KEY_ASTERISK;
						break;
					case '9':
						key = KEY_LEFTPARENTHESIS;
						break;
				}
            }
			else {

				switch (key) {
					case KEY_COMMA:
						key = KEY_LESS;
						break;

					case KEY_DOT:
						key = KEY_GREATER;
						break;

					case KEY_SLASH:
						key = KEY_QUESTION;
						break;

					case KEY_SEMICOLON:
						key = KEY_COLON;
						break;

					case KEY_QUOTE:
						key = KEY_QUOTEDOUBLE;
						break;

					case KEY_LEFTBRACKET :
						key = KEY_LEFTCURL;
						break;

					case KEY_RIGHTBRACKET :
						key = KEY_RIGHTCURL;
						break;

					case KEY_GRAVE:
						key = KEY_TILDE;
						break;

					case KEY_MINUS:
						key = KEY_UNDERSCORE;
						break;

					case KEY_PLUS:
						key = KEY_EQUAL;
						break;

					case KEY_BACKSLASH:
						key = KEY_BAR;
						break;
				}
			}
        }

		//! return the key
		return key;
	}

	//! scan code != a valid ascii char so no convertion is possible
	return 0;
}

char key_stroke_listener () {

	int code = 0;

	//! read scan code only if the kkybrd controller output buffer is full (scan code is in it)
	while (!(kybrd_ctrl_read_status () & KYBRD_CTRL_STATS_MASK_OUT_BUF)) {}
    //! read the scan code
    code = (int) kybrd_enc_read_buf ();

    //! test if this is a break code (Original XT Scan Code Set specific)
    if (code & 0x80) {	//test bit 7
        // out_description("Break code", code); DEBUG

        //! covert the break code into its make code equivelant
        code -= 0x80;

        //! grab the key
        int key = kkybrd_scancode_std [code];

        //! test if a special key has been released & set it
        switch (key) {
            case KEY_LSHIFT:
            case KEY_RSHIFT:
                shift = false;
                break;
            default:
                return kybrd_key_to_ascii(key);
        }
    }
    else {
        //out_description("Make code", code); DEBUG

        //! this is a make code - set the scan code
        scancode = code;

        //! grab the key
        int key = kkybrd_scancode_std [code];

        //! test if user is holding down any special keys & set it
        switch (key) {

            case KEY_LSHIFT:
            case KEY_RSHIFT:
                shift = true;
                break;

            case KEY_CAPSLOCK:
                capslock = (capslock) ? false : true;
                kkybrd_set_leds (false, capslock, false);
                break;
        }
    }
    return 0;
}

