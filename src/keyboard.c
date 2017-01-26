#include "asm.h"
#include "platform.h"
#include "tcg.h"
#include "util.h"
#include "keyboard.h"

static int scancode;
static bool shift, capslock;

enum KYBRD_ENCODER_IO { KYBRD_ENC_INPUT_BUF = 0x60, KYBRD_ENC_CMD_REG = 0x60 };

enum KYBRD_CTRL_IO { KYBRD_CTRL_STATS_REG = 0x64, KYBRD_CTRL_CMD_REG = 0x64 };

enum KYBRD_CTRL_STATS_MASK {

  KYBRD_CTRL_STATS_MASK_OUT_BUF = 0x01,  // 00000001
  KYBRD_CTRL_STATS_MASK_IN_BUF = 0x02,   // 00000010
  KYBRD_CTRL_STATS_MASK_SYSTEM = 0x04,   // 00000100
  KYBRD_CTRL_STATS_MASK_CMD_DATA = 0x08, // 00001000
  KYBRD_CTRL_STATS_MASK_LOCKED = 0x10,   // 00010000
  KYBRD_CTRL_STATS_MASK_AUX_BUF = 0x20,  // 00100000
  KYBRD_CTRL_STATS_MASK_TIMEOUT = 0x40,  // 01000000
  KYBRD_CTRL_STATS_MASK_PARITY = 0x80    // 10000000
};

enum KYBRD_ENC_CMDS {

  KYBRD_ENC_CMD_SET_LED = 0xED,
  KYBRD_ENC_CMD_ECHO = 0xEE,
  KYBRD_ENC_CMD_SCAN_CODE_SET = 0xF0,
  KYBRD_ENC_CMD_ID = 0xF2,
  KYBRD_ENC_CMD_AUTODELAY = 0xF3,
  KYBRD_ENC_CMD_ENABLE = 0xF4,
  KYBRD_ENC_CMD_RESETWAIT = 0xF5,
  KYBRD_ENC_CMD_RESETSCAN = 0xF6,
  KYBRD_ENC_CMD_ALL_AUTO = 0xF7,
  KYBRD_ENC_CMD_ALL_MAKEBREAK = 0xF8,
  KYBRD_ENC_CMD_ALL_MAKEONLY = 0xF9,
  KYBRD_ENC_CMD_ALL_MAKEBREAK_AUTO = 0xFA,
  KYBRD_ENC_CMD_SINGLE_AUTOREPEAT = 0xFB,
  KYBRD_ENC_CMD_SINGLE_MAKEBREAK = 0xFC,
  KYBRD_ENC_CMD_SINGLE_BREAKONLY = 0xFD,
  KYBRD_ENC_CMD_RESEND = 0xFE,
  KYBRD_ENC_CMD_RESET = 0xFF
};

enum KEYCODE {

  // Alphanumeric keys ////////////////

  KEY_SPACE = ' ',
  KEY_0 = '0',
  KEY_1 = '1',
  KEY_2 = '2',
  KEY_3 = '3',
  KEY_4 = '4',
  KEY_5 = '5',
  KEY_6 = '6',
  KEY_7 = '7',
  KEY_8 = '8',
  KEY_9 = '9',

  KEY_A = 'a',
  KEY_B = 'b',
  KEY_C = 'c',
  KEY_D = 'd',
  KEY_E = 'e',
  KEY_F = 'f',
  KEY_G = 'g',
  KEY_H = 'h',
  KEY_I = 'i',
  KEY_J = 'j',
  KEY_K = 'k',
  KEY_L = 'l',
  KEY_M = 'm',
  KEY_N = 'n',
  KEY_O = 'o',
  KEY_P = 'p',
  KEY_Q = 'q',
  KEY_R = 'r',
  KEY_S = 's',
  KEY_T = 't',
  KEY_U = 'u',
  KEY_V = 'v',
  KEY_W = 'w',
  KEY_X = 'x',
  KEY_Y = 'y',
  KEY_Z = 'z',

  KEY_RETURN = '\r',
  KEY_ESCAPE = 0x1001,
  KEY_BACKSPACE = '\b',

  // Arrow keys ////////////////////////

  KEY_UP = 0x1100,
  KEY_DOWN = 0x1101,
  KEY_LEFT = 0x1102,
  KEY_RIGHT = 0x1103,

  // Function keys /////////////////////

  KEY_F1 = 0x1201,
  KEY_F2 = 0x1202,
  KEY_F3 = 0x1203,
  KEY_F4 = 0x1204,
  KEY_F5 = 0x1205,
  KEY_F6 = 0x1206,
  KEY_F7 = 0x1207,
  KEY_F8 = 0x1208,
  KEY_F9 = 0x1209,
  KEY_F10 = 0x120a,
  KEY_F11 = 0x120b,
  KEY_F12 = 0x120b,
  KEY_F13 = 0x120c,
  KEY_F14 = 0x120d,
  KEY_F15 = 0x120e,

  KEY_DOT = '.',
  KEY_COMMA = ',',
  KEY_COLON = ':',
  KEY_SEMICOLON = ';',
  KEY_SLASH = '/',
  KEY_BACKSLASH = '\\',
  KEY_PLUS = '+',
  KEY_MINUS = '-',
  KEY_ASTERISK = '*',
  KEY_EXCLAMATION = '!',
  KEY_QUESTION = '?',
  KEY_QUOTEDOUBLE = '\"',
  KEY_QUOTE = '\'',
  KEY_EQUAL = '=',
  KEY_HASH = '#',
  KEY_PERCENT = '%',
  KEY_AMPERSAND = '&',
  KEY_UNDERSCORE = '_',
  KEY_LEFTPARENTHESIS = '(',
  KEY_RIGHTPARENTHESIS = ')',
  KEY_LEFTBRACKET = '[',
  KEY_RIGHTBRACKET = ']',
  KEY_LEFTCURL = '{',
  KEY_RIGHTCURL = '}',
  KEY_DOLLAR = '$',
  KEY_POUND = '#',
  KEY_EURO = '$',
  KEY_LESS = '<',
  KEY_GREATER = '>',
  KEY_BAR = '|',
  KEY_GRAVE = '`',
  KEY_TILDE = '~',
  KEY_AT = '@',
  KEY_CARRET = '^',

  // Numeric keypad //////////////////////

  KEY_KP_0 = '0',
  KEY_KP_1 = '1',
  KEY_KP_2 = '2',
  KEY_KP_3 = '3',
  KEY_KP_4 = '4',
  KEY_KP_5 = '5',
  KEY_KP_6 = '6',
  KEY_KP_7 = '7',
  KEY_KP_8 = '8',
  KEY_KP_9 = '9',
  KEY_KP_PLUS = '+',
  KEY_KP_MINUS = '-',
  KEY_KP_DECIMAL = '.',
  KEY_KP_DIVIDE = '/',
  KEY_KP_ASTERISK = '*',
  KEY_KP_NUMLOCK = 0x300f,
  KEY_KP_ENTER = 0x3010,

  KEY_TAB = 0x4000,
  KEY_CAPSLOCK = 0x4001,

  // Modify keys ////////////////////////////

  KEY_LSHIFT = 0x4002,
  KEY_LCTRL = 0x4003,
  KEY_LALT = 0x4004,
  KEY_LWIN = 0x4005,
  KEY_RSHIFT = 0x4006,
  KEY_RCTRL = 0x4007,
  KEY_RALT = 0x4008,
  KEY_RWIN = 0x4009,

  KEY_INSERT = 0x400a,
  KEY_DELETE = 0x400b,
  KEY_HOME = 0x400c,
  KEY_END = 0x400d,
  KEY_PAGEUP = 0x400e,
  KEY_PAGEDOWN = 0x400f,
  KEY_SCROLLLOCK = 0x4010,
  KEY_PAUSE = 0x4011,

  KEY_UNKNOWN,
  KEY_NUMKEYCODES
};

#define isascii(c) ((unsigned)(c) <= 0x7F)

static int kkybrd_scancode_std[] = {
    //! key			scancode
    KEY_UNKNOWN,      // 0
    KEY_ESCAPE,       // 1
    KEY_1,            // 2
    KEY_2,            // 3
    KEY_3,            // 4
    KEY_4,            // 5
    KEY_5,            // 6
    KEY_6,            // 7
    KEY_7,            // 8
    KEY_8,            // 9
    KEY_9,            // 0xa
    KEY_0,            // 0xb
    KEY_MINUS,        // 0xc
    KEY_EQUAL,        // 0xd
    KEY_BACKSPACE,    // 0xe
    KEY_TAB,          // 0xf
    KEY_Q,            // 0x10
    KEY_W,            // 0x11
    KEY_E,            // 0x12
    KEY_R,            // 0x13
    KEY_T,            // 0x14
    KEY_Y,            // 0x15
    KEY_U,            // 0x16
    KEY_I,            // 0x17
    KEY_O,            // 0x18
    KEY_P,            // 0x19
    KEY_LEFTBRACKET,  // 0x1a
    KEY_RIGHTBRACKET, // 0x1b
    KEY_RETURN,       // 0x1c
    KEY_LCTRL,        // 0x1d
    KEY_A,            // 0x1e
    KEY_S,            // 0x1f
    KEY_D,            // 0x20
    KEY_F,            // 0x21
    KEY_G,            // 0x22
    KEY_H,            // 0x23
    KEY_J,            // 0x24
    KEY_K,            // 0x25
    KEY_L,            // 0x26
    KEY_SEMICOLON,    // 0x27
    KEY_QUOTE,        // 0x28
    KEY_GRAVE,        // 0x29
    KEY_LSHIFT,       // 0x2a
    KEY_BACKSLASH,    // 0x2b
    KEY_Z,            // 0x2c
    KEY_X,            // 0x2d
    KEY_C,            // 0x2e
    KEY_V,            // 0x2f
    KEY_B,            // 0x30
    KEY_N,            // 0x31
    KEY_M,            // 0x32
    KEY_COMMA,        // 0x33
    KEY_DOT,          // 0x34
    KEY_SLASH,        // 0x35
    KEY_RSHIFT,       // 0x36
    KEY_KP_ASTERISK,  // 0x37
    KEY_RALT,         // 0x38
    KEY_SPACE,        // 0x39
    KEY_CAPSLOCK,     // 0x3a
    KEY_F1,           // 0x3b
    KEY_F2,           // 0x3c
    KEY_F3,           // 0x3d
    KEY_F4,           // 0x3e
    KEY_F5,           // 0x3f
    KEY_F6,           // 0x40
    KEY_F7,           // 0x41
    KEY_F8,           // 0x42
    KEY_F9,           // 0x43
    KEY_F10,          // 0x44
    KEY_KP_NUMLOCK,   // 0x45
    KEY_SCROLLLOCK,   // 0x46
    KEY_HOME,         // 0x47
    KEY_KP_8,         // 0x48	//keypad up arrow
    KEY_PAGEUP,       // 0x49
    KEY_KP_2,         // 0x50	//keypad down arrow
    KEY_KP_3,         // 0x51	//keypad page down
    KEY_KP_0,         // 0x52	//keypad insert key
    KEY_KP_DECIMAL,   // 0x53	//keypad delete key
    KEY_UNKNOWN,      // 0x54
    KEY_UNKNOWN,      // 0x55
    KEY_UNKNOWN,      // 0x56
    KEY_F11,          // 0x57
    KEY_F12           // 0x58
};

//! invalid scan code. Used to indicate the last scan code is not to be reused
const int INVALID_SCANCODE = 0;

//! read status from keyboard controller
static unsigned char kybrd_ctrl_read_status(void) {
  return inb(KYBRD_CTRL_STATS_REG);
}

//! send command byte to keyboard controller
void kybrd_ctrl_send_cmd(BYTE cmd) {

  //! wait for kkybrd controller input buffer to be clear
  while (1)
    if ((kybrd_ctrl_read_status() & KYBRD_CTRL_STATS_MASK_IN_BUF) == 0)
      break;

  outb(KYBRD_CTRL_CMD_REG, cmd);
}

//! read keyboard encoder buffer
static BYTE kybrd_enc_read_buf(void) { return inb(KYBRD_ENC_INPUT_BUF); }

//! send command byte to keyboard encoder
static void kybrd_enc_send_cmd(BYTE cmd) {

  //! wait for kkybrd controller input buffer to be clear
  while (!((kybrd_ctrl_read_status() & KYBRD_CTRL_STATS_MASK_IN_BUF) == 0)) {
  }

  //! send command byte to kybrd encoder
  outb(KYBRD_ENC_CMD_REG, cmd);
}

//! sets leds
static void kkybrd_set_leds(bool num, bool caps, bool scroll) {

  BYTE data = 0;

  //! set or clear the bit
  data = (scroll) ? (data | 1) : (data & 1);
  data = (num) ? (num | 2) : (num & 2);
  data = (caps) ? (num | 4) : (num & 4);

  //! send the command -- update keyboard Light Emetting Diods (LEDs)
  kybrd_enc_send_cmd(KYBRD_ENC_CMD_SET_LED);
  kybrd_enc_send_cmd(data);
}

//! convert key to an ascii character
static char kybrd_key_to_ascii(int code) {

  BYTE key = code;

  //! insure key is an ascii character
  if (isascii(key)) {

    //! if shift key is down or caps lock is on, make the key uppercase
    if (shift || capslock)
      if (key >= 'a' && key <= 'z')
        key -= 32;

    if (shift && !capslock) {
      if (key >= '0' && key <= '9') {
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
      } else {

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

        case KEY_LEFTBRACKET:
          key = KEY_LEFTCURL;
          break;

        case KEY_RIGHTBRACKET:
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

char getchar(void) {
  int code = 0;

  //! read scan code only if the kkybrd controller output buffer is full (scan
  //! code is in it)
  while (!(kybrd_ctrl_read_status() & KYBRD_CTRL_STATS_MASK_OUT_BUF)) {
  }
  //! read the scan code
  code = (int)kybrd_enc_read_buf();

  //! test if this is a break code (Original XT Scan Code Set specific)
  if (code & 0x80) { // test bit 7
    //! covert the break code into its make code equivelant
    code -= 0x80;

    //! grab the key
    int key = kkybrd_scancode_std[code];

    //! test if a special key has been released & set it
    switch (key) {
    case KEY_LSHIFT:
    case KEY_RSHIFT:
      shift = false;
      break;
    default:
      return kybrd_key_to_ascii(key);
    }
  } else {
    //! this is a make code - set the scan code
    scancode = code;

    //! grab the key
    int key = kkybrd_scancode_std[code];

    //! test if user is holding down any special keys & set it
    switch (key) {

    case KEY_LSHIFT:
    case KEY_RSHIFT:
      shift = true;
      break;

    case KEY_CAPSLOCK:
      capslock = (capslock) ? false : true;
      kkybrd_set_leds(false, capslock, false);
      break;
    }
  }
  return 0;
}

int get_string(char *str, unsigned int strSize, bool show) {
  UINT32 i = 0;
  char c =
      getchar(); // for some reason, there's always an 'enter' char
  while (i < strSize) {
    c = getchar();
    if (c == 0x0D)
      break; // user hit 'return'

    if (c != 0) {
      str[i] = c;
      if (show)
        out_char(c);
      i++;
    }
  }
  str[i] = '\0';
  out_char('\n');
  return i;
}
