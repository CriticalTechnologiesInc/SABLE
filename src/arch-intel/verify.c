/*
 * verify.c: verify that platform and processor supports Intel(r) TXT
 *
 * Copyright (c) 2003-2010, Intel Corporation
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
#include <util.h>
#include <uuid.h>
typedef struct __packed {
    uint64_t  base;
    uint64_t  length;
    uint8_t   mem_type;
    uint8_t   reserved[7];
} sinit_mdr_t;
#define MDR_MEMTYPE_GOOD                0x00
#define MDR_MEMTYPE_SMM_OVERLAY         0x01
#define MDR_MEMTYPE_SMM_NONOVERLAY      0x02
#define MDR_MEMTYPE_PCIE_CONFIG_SPACE   0x03
#define MDR_MEMTYPE_PROTECTED           0x04
#include <verify.h>
#include <multiboot.h>
#include <loader.h>
#include <e820.h>
#include <cmdline.h>
#include <processor.h>

/*
 * CPUID extended feature info
 */
static unsigned int g_cpuid_ext_feat_info;

/*
 * IA32_FEATURE_CONTROL_MSR
 */

bool use_mwait(void)
{
    return get_tboot_mwait() && (g_cpuid_ext_feat_info & CPUID_X86_FEATURE_XMM3);
}

bool verify_e820_map(sinit_mdr_t* mdrs_base, uint32_t num_mdrs)
{
    sinit_mdr_t* mdr_entry;
    sinit_mdr_t tmp_entry;
    uint64_t base, length;
    uint32_t i, j, pos;

    if ( (mdrs_base == NULL) || (num_mdrs == 0) )
        return false;

    /* sort mdrs */
    for( i = 0; i < num_mdrs; i++ ) {
        memcpy(&tmp_entry, &mdrs_base[i], sizeof(sinit_mdr_t));
        pos = i;
        for ( j = i + 1; j < num_mdrs; j++ ) {
            if ( ( tmp_entry.base > mdrs_base[j].base )
                 || (( tmp_entry.base == mdrs_base[j].base ) &&
                     ( tmp_entry.length > mdrs_base[j].length )) ) {
                memcpy(&tmp_entry, &mdrs_base[j], sizeof(sinit_mdr_t));
                pos = j;
            }
        }
        if ( pos > i ) {
            memcpy(&mdrs_base[pos], &mdrs_base[i], sizeof(sinit_mdr_t));
            memcpy(&mdrs_base[i], &tmp_entry, sizeof(sinit_mdr_t));
        }
    }

    /* verify e820 map against mdrs */
    /* find all ranges *not* in MDRs:
       if any of it is in e820 as RAM then set that to RESERVED. */
    i = 0;
    base = 0;
    while ( i < num_mdrs ) {
        mdr_entry = &mdrs_base[i];
        i++;
        if ( mdr_entry->mem_type > MDR_MEMTYPE_GOOD )
            continue;
        length = mdr_entry->base - base;
        if ( (length > 0) && (!e820_reserve_ram(base, length)) )
            return false;
        base = mdr_entry->base + mdr_entry->length;
    }

    /* deal with the last gap */
    length = (uint64_t)-1 - base;
    return e820_reserve_ram(base, length);
}
