/*
 * cmdline.c: command line parsing fns
 *
 * Copyright (c) 2006-2012, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <types.h>
#include "util.h"
#include "uuid.h"
#include <cmdline.h>
#include <misc.h>
#include <tboot.h>
#include <ctype.h>
#include <intel_tpm.h>
#include <config.h>

#include <com.h>

extern serial_port_t g_com_port;

serial_port_t g_com_port = {115200, 0, 0x3, COM1_ADDR}; /* com1,115200,8n1 */

int strcmp(s1, s2)
	register const char *s1, *s2;
{
	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);
	return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}

int strncmp(s1, s2, n)
	register const char *s1, *s2;
	register size_t n;
{

	if (n == 0)
		return (0);
	do {
		if (*s1 != *s2++)
			return (*(const unsigned char *)s1 -
				*(const unsigned char *)(s2 - 1));
		if (*s1++ == 0)
			break;
	} while (--n != 0);
	return (0);
}

#define ULONG_MAX     0xFFFFFFFFUL

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long strtoul(const char *nptr, char **endptr, int base)
{
	const char *s = nptr;
	unsigned long acc;
	unsigned char c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	/*
	 * See strtol for comments as to the logic used.
	 */
	do {
		c = *s++;
	} while (isspace(c));
	if (c == '-') {
		neg = 1;
		c = *s++;
	} else if (c == '+')
		c = *s++;
	if ((base == 0 || base == 16) &&
	    c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if (base == 0)
		base = c == '0' ? 8 : 10;
	cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
	cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
	for (acc = 0, any = 0;; c = *s++) {
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = ULONG_MAX;
	} else if (neg)
		acc = -acc;
	if (endptr != 0)
		*((const char **)endptr) = any ? s - 1 : nptr;
	return (acc);
}


char *index(p, ch)
	const char *p;
	int ch;
{
	union {
		const char *cp;
		char *p;
	} u;

	u.cp = p;
	for (;; ++u.p) {
		if (*u.p == ch)
			return(u.p);
		if (*u.p == '\0')
			return(NULL);
	}
	/* NOTREACHED */
}

static __inline char *strchr(const char *p, int ch)
{
	return index(p, ch);
}
/*
 * copy of original command line
 * part of tboot measurement (hence in .text section)
 */

/* Used for kernel command line parameter setup */
typedef struct {
    const char *name;          /* set to NULL for last item in list */
    const char *def_val;
} cmdline_option_t;

#define MAX_VALUE_LEN 64

/*
 * the option names and default values must be separate from the actual
 * params entered
 * this allows the names and default values to be part of the MLE measurement
 * param_values[] need to be in .bss section so that will get cleared on launch
 */

/* global option array for command line */
static const cmdline_option_t g_tboot_cmdline_options[] = {
    { "loglvl",     "all" },         /* all|err,warn,info|none */
    { "logging",    "serial,vga" },  /* vga,serial,memory|none */
    { "serial",     "115200,8n1,0x3f8" },
    /* serial=<baud>[/<clock_hz>][,<DPS>[,<io-base>[,<irq>[,<serial-bdf>[,<bridge-bdf>]]]]] */
    { "vga_delay",  "0" },           /* # secs */
    { "ap_wake_mwait", "false" },    /* true|false */
    { "pcr_map", "legacy" },         /* legacy|da */
    { "min_ram", "0" },              /* size in bytes | 0 for no min */
    { "call_racm", "false" },        /* true|false|check */
    { "measure_nv", "false" },       /* true|false */
    { "extpol",    "sha1" },         /*agile|embedded|sha1|sha256|sm3|... */
    { "ignore_prev_err", "true"},    /* true|false */
    { NULL, NULL }
};
static char g_tboot_param_values[ARRAY_SIZE(g_tboot_cmdline_options)][MAX_VALUE_LEN];

static const cmdline_option_t g_linux_cmdline_options[] = {
    { "vga", "" },
    { "mem", "" },
    { NULL, NULL }
};
static char g_linux_param_values[ARRAY_SIZE(g_linux_cmdline_options)][MAX_VALUE_LEN];

static const char* get_option_val(const cmdline_option_t *options,  char vals[][MAX_VALUE_LEN],    const char *opt_name)
{
    for ( int i = 0; options[i].name != NULL; i++ ) {
        if ( strcmp(options[i].name, opt_name) == 0 )
            return vals[i];
    }
    out_info("requested unknown option\n");
    return NULL;
}

static void cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN])
{
    const char *p = cmdline;
    int i;

    /* copy default values to vals[] */
    for ( i = 0; options[i].name != NULL; i++ ) {
        strncpy(vals[i], options[i].def_val, MAX_VALUE_LEN-1);
        vals[i][MAX_VALUE_LEN-1] = '\0';
    }

    if ( p == NULL )
        return;

    /* parse options */
    while ( true )
    {
        /* skip whitespace */
        while ( isspace(*p) )
            p++;
        if ( *p == '\0' )
            break;

        /* find end of current option */
        const char *opt_start = p;
        const char *opt_end = strchr(opt_start, ' ');
        if ( opt_end == NULL )
            opt_end = opt_start + strlen(opt_start);
        p = opt_end;

        /* find value part; if no value found, use default and continue */
        const char *val_start = strchr(opt_start, '=');
        if ( val_start == NULL || val_start > opt_end )
            continue;
        val_start++;

        unsigned int opt_name_size = val_start - opt_start - 1;
        unsigned int copy_size = opt_end - val_start;
        if ( copy_size > MAX_VALUE_LEN - 1 )
            copy_size = MAX_VALUE_LEN - 1;
        if ( opt_name_size == 0 || copy_size == 0 )
            continue;

        /* value found, so copy it */
        for ( i = 0; options[i].name != NULL; i++ ) {
            if ( strncmp(options[i].name, opt_start, opt_name_size ) == 0 ) {
                strncpy(vals[i], val_start, copy_size);
                vals[i][copy_size] = '\0'; /* add '\0' to the end of string */
                break;
            }
        }
    }
}

void tboot_parse_cmdline(void)
{
    cmdline_parse(g_cmdline, g_tboot_cmdline_options, g_tboot_param_values);
}

void linux_parse_cmdline(const char *cmdline)
{
    cmdline_parse(cmdline, g_linux_cmdline_options, g_linux_param_values);
}

static bool parse_pci_bdf(const char **bdf, uint32_t *bus, uint32_t *slot,
                          uint32_t *func)
{
    *bus = strtoul(*bdf, (char **)bdf, 16);
    if ( **bdf != ':' )
        return false;
    (*bdf)++;
    *slot = strtoul(*bdf, (char **)bdf, 16);
    if ( **bdf != '.' )
        return false;
    (*bdf)++;
    *func = strtoul(*bdf, (char **)bdf, 16);

    return true;
}

bool g_psbdf_enabled = false;
static bool parse_com_psbdf(const char **bdf)
{
    g_psbdf_enabled = parse_pci_bdf(bdf,
                  &g_com_port.comc_psbdf.bus,
                  &g_com_port.comc_psbdf.slot,
                  &g_com_port.comc_psbdf.func);

    return g_psbdf_enabled;
}

bool g_pbbdf_enabled = false;
static bool parse_com_pbbdf(const char **bdf)
{
    g_pbbdf_enabled = parse_pci_bdf(bdf,
                  &g_com_port.comc_pbbdf.bus,
                  &g_com_port.comc_pbbdf.slot,
                  &g_com_port.comc_pbbdf.func);

    return g_pbbdf_enabled;
}

static bool parse_com_fmt(const char **fmt)
{
    /* fmt:  <5|6|7|8><n|o|e|m|s><0|1> */
    /* default 8n1 */
    uint8_t data_bits = 8;
    uint8_t parity = 'n';
    uint8_t stop_bits = 1;


    /* must specify all values */
    if ( strlen(*fmt) < 3 )
        return false;

    /* data bits */
    if ( **fmt >= '5' && **fmt <= '8' )
        data_bits = **fmt - '0';
    else
        return false;
    (*fmt)++;

    /* parity */
    if ( **fmt == 'n' || **fmt == 'o' || **fmt == 'e' || **fmt == 'm' ||
         **fmt == 's' )
        parity = **fmt;
    else
        return false;
    (*fmt)++;

    /* stop bits */
    if ( **fmt == '0' || **fmt == '1' )
        stop_bits = **fmt - '0';
    else
        return false;
    (*fmt)++;

    g_com_port.comc_fmt = GET_LCR_VALUE(data_bits, stop_bits, parity);

    return true;
}

static bool parse_serial_param(const char *com)
{
    /* parse baud */
    g_com_port.comc_curspeed = strtoul(com, (char **)&com, 10);
    if ( (g_com_port.comc_curspeed < 1200) ||
         (g_com_port.comc_curspeed > 115200) )
        return false;

    /* parse clock hz */
    if ( *com == '/' ) {
        ++com;
        g_com_port.comc_clockhz = strtoul(com, (char **)&com, 0) << 4;
        if ( g_com_port.comc_clockhz == 0 )
            return false;
    }

    /* parse data_bits/parity/stop_bits */
    if ( *com != ',' )
        goto exit;
    ++com;
    while ( isspace(*com) )
        com++;
    if ( !parse_com_fmt(&com) )
        return false;

    /* parse IO base */
    if ( *com != ',' )
        goto exit;
    ++com;
    g_com_port.comc_port = strtoul(com, (char **)&com, 0);
    if ( g_com_port.comc_port == 0 )
        return false;

    /* parse irq */
    if ( *com != ',' )
        goto exit;
    ++com;
    g_com_port.comc_irq = strtoul(com, (char **)&com, 10);
    if ( g_com_port.comc_irq == 0 )
        return false;

    /* parse PCI serial controller bdf */
    if ( *com != ',' )
        goto exit;
    ++com;
    if ( !parse_com_psbdf(&com) )
        return false;

    /* parse PCI bridge bdf */
    if ( *com != ',' )
        goto exit;
    ++com;
    if ( !parse_com_pbbdf(&com) )
        return false;

 exit:
    return true;
}

bool get_tboot_serial(void)
{
    const char *serial = get_option_val(g_tboot_cmdline_options,
                                        g_tboot_param_values, "serial");
    if ( serial == NULL || *serial == '\0' )
        return false;

    return parse_serial_param(serial);
}

bool get_tboot_prefer_da(void)
{
    const char *value = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "pcr_map");
    if ( value != NULL && strcmp(value, "da") == 0 )
        return true;

    return false;
}

extern uint32_t g_min_ram;
void get_tboot_min_ram(void)
{
    const char *min_ram = get_option_val(g_tboot_cmdline_options,
                                         g_tboot_param_values, "min_ram");
    if ( min_ram == NULL )
        return;

    g_min_ram = strtoul(min_ram, NULL, 0);
}

bool get_tboot_mwait(void)
{
    const char *mwait = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "ap_wake_mwait");
    if ( mwait == NULL || strcmp(mwait, "false") == 0 )
        return false;
    return true;
}

bool get_tboot_call_racm(void)
{
    const char *call_racm = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "call_racm");
    if ( call_racm == NULL || strcmp(call_racm, "true") != 0 )
        return false;
    return true;
}

bool get_tboot_call_racm_check(void)
{
    const char *call_racm = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "call_racm");
    if ( call_racm == NULL || strcmp(call_racm, "check") != 0 )
        return false;
    return true;
}

bool get_tboot_measure_nv(void)
{
    const char *measure_nv = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "measure_nv");
    if ( measure_nv == NULL || strcmp(measure_nv, "true") != 0 )
        return false;
    return true;
}

bool get_tboot_ignore_prev_err(void)
{
    const char *ignore_prev_err = 
	    get_option_val(g_tboot_cmdline_options,
			   g_tboot_param_values,
			   "ignore_prev_err");
    if ( ignore_prev_err == NULL || strcmp(ignore_prev_err, "true") == 0 )
	    return true;
    return false;
}

/*
 * linux kernel command line parsing
 */

bool get_linux_vga(int *vid_mode)
{
    const char *vga = get_option_val(g_linux_cmdline_options,
                                     g_linux_param_values, "vga");
    if ( vga == NULL || vid_mode == NULL )
        return false;

    if ( strcmp(vga, "normal") == 0 )
        *vid_mode = 0xFFFF;
    else if ( strcmp(vga, "ext") == 0 )
        *vid_mode = 0xFFFE;
    else if ( strcmp(vga, "ask") == 0 )
        *vid_mode = 0xFFFD;
    else
        *vid_mode = strtoul(vga, NULL, 0);

    return true;
}

bool get_linux_mem(uint64_t *max_mem)
{
    char *last = NULL;
    const char *mem = get_option_val(g_linux_cmdline_options,
                                     g_linux_param_values, "mem");
    if ( mem == NULL || max_mem == NULL )
        return false;

    *max_mem = strtoul(mem, &last, 0);
    if ( *max_mem == 0 )
        return false;

    if ( last == NULL )
        return true;

    switch ( *last ) {
        case 'G':
        case 'g':
            *max_mem = *max_mem << 30;
            return true;
        case 'M':
        case 'm':
            *max_mem = *max_mem << 20;
            return true;
        case 'K':
        case 'k':
            *max_mem = *max_mem << 10;
            return true;
        default:
            return false;
    }

    return true;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
