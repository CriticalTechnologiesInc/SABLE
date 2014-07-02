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


#include <string.h>
#include <stdarg.h>
#include "util.h"

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
__exit(unsigned status)
{
  out_char('\n');
  out_description("exit()", status);
  for (unsigned i=0; i<1000;i++)
    {
      wait(1000);
      //out_char('.');
    }
  out_string("-> OK, reboot now!\n");
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
  CHECK3(-31,0x8000000A > cpuid_eax(0x80000000), "no ext cpuid");
  CHECK3(-32,!(0x4   & cpuid_ecx(0x80000001)), "no SVM support");
  CHECK3(-33,!(0x200 & cpuid_edx(0x80000001)), "no APIC support");
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
  CHECK3(-40, !(rdmsr(MSR_EFER) & EFER_SVME), "could not enable SVM");
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

unsigned char bData[16];
unsigned char idx=0;
unsigned char tmp=0; 

volatile byte shiftSet = 0;

char kbBuffer[16];
char kbPos = 0;
char kbSize = 0;
char capsSet = 0;
volatile byte extFlag = 0;
volatile byte relFlag = 0;
volatile byte key=0; 


char keyhit()
{
  return kbSize != 0;
}

unsigned char waitKey()
{
  unsigned char k = 0;
  while(kbSize == 0);
  k = kbBuffer[(kbPos - kbSize)&0x0F];
  kbSize--;
  return k;
} 

unsigned char readByte()
{
    int i=0, t=0;
    idx=0;
    tmp=0;

    i=0;
    goto dataread;
   // while(INPUT(CLOCK) != 0);   // Wait for a keypress
            t=0;
       while(INPUT(CLOCK) != 0 && t<255)   // Wait for clock, time out if needed
       {
           delay_us(1);
           t++;
       }
    for(i=0; i<11; i++)
    {
        t=0;
        while(INPUT(CLOCK) != 0 && t<255)   // Wait for clock, time out if needed
        {
            delay_us(1);
            t++;
        }
        dataread:

        bData[idx]=INPUT(DATA);
        idx++;
        if(idx==9)
        {
            for(idx=1; idx<9; idx++)
                if(bData[idx]!=0)
                    tmp|=(1<<(idx-1));

            return tmp;
            idx=0;
            tmp=0;
        }
     //   while(INPUT(CLOCK) == 0);
        t=0;
        while(INPUT(CLOCK) == 0 && t<255)   // Wait for clock, time out if needed
        {
            delay_us(1);
            t++;
        }

    }
} 

static const unsigned char scantableAZ[]={
0x1C, 0x32, 0x21, 0x23, 0x24, 0x2B, 0x34, 0x33, 0x43, 0x3B, 0x42, 0x4B, 0x3A, // A-Z
0x31, 0x44, 0x4D, 0x15, 0x2D, 0x1B, 0x2C, 0x3C, 0x2A, 0x1D, 0x22, 0x35, 0x1A};


// Normal numeric scancodes, starting with ',' .
static const unsigned char scantable09n[]=
{
0x41, 0x4E, 0x49, 0x4A, // , - . /
0x45, 0x16, 0x1E, 0x26, 0x25, 0x2E, 0x36, 0x3D, 0x3E, 0x46,     //Digits 0-9
0x00, 0x4C, 0x00, 0x55 // 0 ; 0 =
};

// Shift scancodes, starting at '!'
static const unsigned char scantable09s[]=
{
    0x16, 0x52, 0x26, 0x25, 0x2E, 0x3D, 0x00, 0x46, 0x45, 0x3E, 0x55
};

// Normal misc. scancode map. Scancode, ASCII value
static const unsigned char scanmapn[]=
{0x54, '[', 0x5B, ']', 0x0E, '`', 0x5D, '\\', 0x52, '\''};

// Shifted misc. scancode map. Scancode, ASCII value
static const unsigned char scanmaps[]=
{0x1E, '@', 0x36, '^', 0x4E, '_', 0x54, '{', 0x5B, '}', 0x5D, '|',
0x4C, ':', 0x41, '<', 0x49, '>', 0x4A, '?', 0x0E, '~'};


// Scancode map independent of Shift
static const unsigned char scanmapx[]=
{0x29, ' ', 0x5A, '\r', 0x0D, '\t', 0x76, 27, 0x66, 0x08};

// Extended scancode map
static const unsigned char scanmape[]=
{
0x71, 0x7F
}; 

unsigned char translate(unsigned char scancode)
{
    int i=0;

    if(extFlag == 0)
    {
        for(i=0; i<10; i+=2)
            if(scanmapx[i] == scancode)
                return scanmapx[i+1];

        for(i=0; i<26; i++)
            if(scantableAZ[i] == scancode)
                if(shiftSet ^ capsSet)
                    return i+65;
                else
                    return i+65 + 32;

        if(shiftSet)
        {
            for(i=0; i<11; i++)
                if(scantable09s[i] == scancode)
                    return i+'!';

            for(i=0; i<22; i+=2)
                if(scanmaps[i] == scancode)
                    return scanmaps[i+1];
        } else
        {
            for(i=0; i<18; i++)
                if(scantable09n[i] == scancode)
                    return i+',';

            for(i=0; i<10; i+=2)
                if(scanmapn[i] == scancode)
                    return scanmapn[i+1];
        }
    } else      // Extended keys
    {
        for(i=0; i<2; i+=2)
            if(scanmape[i] == scancode)
                return scanmape[i+1];
    }
    return '?';
} 

unsigned char processByte()
{
    unsigned char i, j;
    i = readByte();

    if(i == 0xF0)       //A key is being released
    {
        relFlag = 1;
        return 0;
    }

    if(i == 0xE0)       // Extended key operation
    {
        extFlag = 1;
        relFlag = 0;    //0xE0 always first in sequence, OK to clear this
        return 0;
    }

    if(relFlag == 0)    // Pressing a key
    {
        if(extFlag == 0)    // Non-extended key pressed
        {
            if(i == 0x12 || i == 0x59)
            {
                shiftSet = 1;
                return 0;
            }

            if(i == 0x58)
            {
                sendByte(0xED);
                if(capsSet == 0)
                {
                    capsSet = 1;
                    sendByte(0x04);
                } else
                {
                    capsSet = 0;
                    sendByte(0x00);
                }
                return 0;
            }


        }
        j = translate(i);
        extFlag = 0;
        return j; 
    }

    if(relFlag == 1)    //Releasing a key
    {
        relFlag = 0;    //If a flag was set but not handled, we wouldn't have gotten here
        extFlag = 0;    //OK to clear this here

        if(extFlag == 0)   // Releasing a nonextended key
        {
            if(i == 0x12 || i == 0x59)
            {
                shiftSet = 0;
                return 0;
            }

        }
//        } else              // Releasing an extended key
//        {
//            return 0;
//        }

//        return 0;
    }
    return 0;
} 
