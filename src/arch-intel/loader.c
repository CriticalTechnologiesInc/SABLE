/*
 * loader.c: support functions for manipulating ELF/Linux kernel
 *           binaries
 *
 * Copyright (c) 2006-2013, Intel Corporation
 * Copyright (c) 2016 Real-Time Systems GmbH
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

#include "types.h"
#include "multiboot.h"
#include "util.h"
#include <uuid.h>
#include "loader.h"
#include <e820.h>
#include <elf_defns.h>
#include <linux_defns.h>
#include <page.h>

bool elf64 = false;
extern memory_map_t *get_e820_copy(void);
extern unsigned int get_nr_map(void);

/* multiboot struct saved so that post_launch() can use it (in tboot.c) */
extern loader_ctx *g_ldr_ctx;
extern bool expand_linux_image(const void *linux_image, size_t linux_size,
                               const void *initrd_image, size_t initrd_size,
                               void **entry_point, bool is_measured_launch);
extern bool is_sinit_acmod(const void *acmod_base, uint32_t acmod_size, 
                           bool quiet);
#define LOADER_CTX_BAD(xctx) \
	xctx == NULL ? 1 : \
	xctx->addr == NULL ? 1 : \
	xctx->type != 1 && xctx->type != 2 ? 1 : 0

static module_t 
*get_module_mb1(const multiboot_info_t *mbi, unsigned int i)
{
    if ( mbi == NULL ) {
        out_info("Error: mbi pointer is zero.\n");
        return NULL;
    }

    if ( i >= mbi->mods_count ) {
        out_info("invalid module #\n");
        return NULL;
    }

    return (module_t *)(mbi->mods_addr + i * sizeof(module_t));
}

static struct mb2_tag
*next_mb2_tag(struct mb2_tag *start)
{
    /* given "start", what's the beginning of the next tag */
    void *addr = (void *) start;
    if (start == NULL)
        return NULL;
    if (start->type == MB2_TAG_TYPE_END)
        return NULL;
    addr += ((start->size + 7) & ~7);
    return (struct mb2_tag *) addr;
}

static struct mb2_tag 
*find_mb2_tag_type(struct mb2_tag *start, uint32_t tag_type)
{
    while (start != NULL){
        if (start->type == tag_type)
            return start;
        start = next_mb2_tag(start);
    }
    return start;
}

static module_t 
*get_module_mb2(loader_ctx *lctx, unsigned int i)
{
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    unsigned int ii;
    struct mb2_tag_module *tag_mod = NULL;
    module_t *mt = NULL;
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
    if (start != NULL){
        for (ii = 1; ii <= i; ii++){
            if (start == NULL)
                return NULL;
            else {
                /* nudge off this hit */
                start = next_mb2_tag(start);
                start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
            }
        }
        /* if we're here, we have the tag struct for the desired module */
        tag_mod = (struct mb2_tag_module *) start;
        mt = (module_t *) &(tag_mod->mod_start);
    }
    return mt;
}

bool verify_loader_context(loader_ctx *lctx)
{
    unsigned int count;
    if (LOADER_CTX_BAD(lctx))
        return false;
    count = get_module_count(lctx);
    if (count < 1){
        out_description("Error: no MB modules ", lctx->type);
        return false;
    } else
        return true;
}

static void *remove_module(loader_ctx *lctx, void *mod_start)
{
    module_t *m = NULL;
    unsigned int i;

    if ( !verify_loader_context(lctx))
        return NULL;

    for ( i = 0; i < get_module_count(lctx); i++ ) {
        m = get_module(lctx, i);
        if ( mod_start == NULL || (void *)m->mod_start == mod_start )
            break;
    }

    /* not found */
    if ( m == NULL ) {
        out_info("could not find module to remove\n");
        return NULL;
    }

    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        /* if we're removing the first module (i.e. the "kernel") then */
        /* need to adjust some mbi fields as well */
        multiboot_info_t *mbi = (multiboot_info_t *) lctx->addr;
        if ( mod_start == NULL ) {
            mbi->cmdline = m->string;
            mbi->flags |= MBI_CMDLINE;
            mod_start = (void *)m->mod_start;
        }

        /* copy remaing mods down by one */
        memcpy(m, m + 1, (mbi->mods_count - i - 1)*sizeof(module_t));

        mbi->mods_count--;

        return mod_start;
    }
    return NULL;
}

//static bool 
//find_module(loader_ctx *lctx, void **base, size_t *size,
//            const void *data, size_t len)
//{
//    if ( lctx == NULL || lctx->addr == NULL) {
//        out_info("Error: context pointer is zero.\n");
//        return false;
//    }
//
//    if ( base == NULL ) {
//        out_info("Error: base is NULL.\n");
//        return false;
//    }
//
//    *base = NULL;
//    if ( size != NULL )
//        *size = 0;
//
//    if ( 0 == get_module_count(lctx)) {
//        out_info("Error: no module.\n");
//        return false;
//    }
//
//    for ( unsigned int i = get_module_count(lctx) - 1; i > 0; i-- ) {
//        module_t *m = get_module(lctx, i);
//        /* check size */
//        size_t mod_size = m->mod_end - m->mod_start;
//        if ( len > mod_size ) {
//            out_info("Error: image size is smaller than data size.\n");
//            return false;
//        }
//        if ( memcmp((void *)m->mod_start, data, len) == 0 ) {
//            *base = (void *)m->mod_start;
//            if ( size != NULL )
//                *size = mod_size;
//            return true;
//        }
//    }
//
//    return false;
//}
//
//bool 
//find_lcp_module(loader_ctx *lctx, void **base, uint32_t *size)
//{
//    size_t size2 = 0;
//    void *base2 = NULL;
//
//    if ( base != NULL )
//        *base = NULL;
//    if ( size != NULL )
//        *size = 0;
//
//    /* try policy data file for old version (0x00 or 0x01) */
//    find_module_by_uuid(lctx, &base2, &size2, &((uuid_t)LCP_POLICY_DATA_UUID));
//
//    /* not found */
//    if ( base2 == NULL ) {
//        /* try policy data file for new version (0x0202) */
//        find_module_by_file_signature(lctx, &base2, &size2,
//                                      LCP_POLICY_DATA_FILE_SIGNATURE);
//
//        if ( base2 == NULL ) {
//            out_info(TBOOT_WARN"no LCP module found\n");
//            return false;
//        }
//        else
//            out_info(TBOOT_INFO"v2 LCP policy data found\n");
//    }
//    else
//        out_info(TBOOT_INFO"v1 LCP policy data found\n");
//
//
//    if ( base != NULL )
//        *base = base2;
//    if ( size != NULL )
//        *size = size2;
//    return true;
//}

/*
 * remove (all) SINIT and LCP policy data modules (if present)
 */

bool 
remove_txt_modules(loader_ctx *lctx)
{
    if ( 0 == get_module_count(lctx)) {
        out_info("Error: no module.\n");
        return 1;
    }

    /* start at end of list so that we can remove w/in the loop */
    for ( unsigned int i = get_module_count(lctx) - 1; i > 0; i-- ) {
        module_t *m = get_module(lctx, i);
        void *base = (void *)m->mod_start;

        if ( is_sinit_acmod(base, m->mod_end - (unsigned long)base, true) ) {
            out_description("got sinit match on module #", i);
            if ( remove_module(lctx, base) == NULL ) {
                out_info(
                       "failed to remove SINIT module from module list\n");
                return 1;
            }
        }
    }

//    void *base = NULL;
//    if ( find_lcp_module(lctx, &base, NULL) ) {
//        if ( remove_module(lctx, base) == NULL ) {
//            out_info("failed to remove LCP module from module list\n");
//            return 1;
//        }
//    }
//
    return 0;
}

static unsigned long max(unsigned long a, unsigned long b)
{
    return (a > b) ? a : b;
}

static 
unsigned long get_mbi_mem_end_mb1(const multiboot_info_t *mbi)
{
    unsigned long end = (unsigned long)(mbi + 1);

    if ( mbi->flags & MBI_CMDLINE )
        end = max(end, mbi->cmdline + strlen((char *)mbi->cmdline) + 1);
    if ( mbi->flags & MBI_MODULES ) {
        end = max(end, mbi->mods_addr + mbi->mods_count * sizeof(module_t));
        unsigned int i;
        for ( i = 0; i < mbi->mods_count; i++ ) {
            module_t *p = get_module_mb1(mbi, i);
            if ( p == NULL )
                break;
            end = max(end, p->string + strlen((char *)p->string) + 1);
        }
    }
    if ( mbi->flags & MBI_AOUT ) {
        const aout_t *p = &(mbi->syms.aout_image);
        end = max(end, p->addr + p->tabsize
                       + sizeof(unsigned long) + p->strsize);
    }
    if ( mbi->flags & MBI_ELF ) {
        const elf_t *p = &(mbi->syms.elf_image);
        end = max(end, p->addr + p->num * p->size);
    }
    if ( mbi->flags & MBI_MEMMAP )
        end = max(end, mbi->mmap_addr + mbi->mmap_length);
    if ( mbi->flags & MBI_DRIVES )
        end = max(end, mbi->drives_addr + mbi->drives_length);
    /* mbi->config_table field should contain */
    /*  "the address of the rom configuration table returned by the */
    /*  GET CONFIGURATION bios call", so skip it */
    if ( mbi->flags & MBI_BTLDNAME )
        end = max(end, mbi->boot_loader_name
                       + strlen((char *)mbi->boot_loader_name) + 1);
    if ( mbi->flags & MBI_APM )
        /* per Grub-multiboot-Main Part2 Rev94-Structures, apm size is 20 */
        end = max(end, mbi->apm_table + 20);
    if ( mbi->flags & MBI_VBE ) {
        /* VBE2.0, VBE Function 00 return 512 bytes*/
        end = max(end, mbi->vbe_control_info + 512);
        /* VBE2.0, VBE Function 01 return 256 bytes*/
        end = max(end, mbi->vbe_mode_info + 256);
    }

    return PAGE_UP(end);
}

module_t *get_module(loader_ctx *lctx, unsigned int i)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;
    if (lctx->type == MB1_ONLY){
        return(get_module_mb1((multiboot_info_t *) lctx->addr, i));
    } else {
        /* so currently, must be type 2 */
        return(get_module_mb2(lctx, i));
    }
}

static void *remove_first_module(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;
    return(remove_module(lctx, NULL));
}

bool launch_kernel(bool is_measured_launch)
{
    void *kernel_entry_point;
    remove_txt_modules(g_ldr_ctx);

    module_t *m = get_module(g_ldr_ctx,0);

    void *kernel_image = (void *)m->mod_start;
    size_t kernel_size = m->mod_end - m->mod_start;

    kernel_image = remove_first_module(g_ldr_ctx);
    if ( kernel_image == NULL )
        return false;

    void *initrd_image;
    size_t initrd_size;

    if ( get_module_count(g_ldr_ctx) == 0 ) {
        initrd_size = 0;
        initrd_image = 0;
    }
    else {
        m = get_module(g_ldr_ctx,0);
        initrd_image = (void *)m->mod_start;
        initrd_size = m->mod_end - m->mod_start;
    }

    bool status = expand_linux_image(kernel_image, kernel_size,
                       initrd_image, initrd_size,
                       &kernel_entry_point, is_measured_launch);
    if(!status)
    {
        out_info("expand_linux_image FAILED!");
        while(1);
    }

    out_info("transfering control to kernel");
    return jump_linux_image(kernel_entry_point);
}

///*
// * find_module_by_uuid
// *
// * find a module by its uuid
// *
// */
//bool find_module_by_uuid(loader_ctx *lctx, void **base, size_t *size,
//                         const uuid_t *uuid)
//{
//    return find_module(lctx, base, size, uuid, sizeof(*uuid));
//}

/*
 * find_module_by_file_signature
 *
 * find a module by its file signature
 *
 */
//bool 
//find_module_by_file_signature(loader_ctx *lctx, void **base,
//                              size_t *size, const char* file_signature)
//{
//    return find_module(lctx, base, size, 
//                       file_signature, strlen(file_signature));
//}
//
bool 
verify_modules(loader_ctx *lctx)
{
    uint64_t base, size;
    module_t *m;
    uint32_t module_count;

    if (LOADER_CTX_BAD(lctx))
        return false;
        
    module_count = get_module_count(lctx);
        
    /* verify e820 map to make sure each module is OK in e820 map */
    /* check modules in mbi should be in RAM */
    for ( unsigned int i = 0; i < module_count; i++ ) {
        m = get_module(lctx,i);
        base = m->mod_start;
        size = m->mod_end - m->mod_start;
        out_info("verifying module of mbi (in e820 table\n\t");
        if ( e820_check_region(base, size) != E820_RAM ) {
            out_info(": failed.\n");
            return false;
        }
        else
            out_info(": succeeded.\n");
    }
    return true;
}

char *get_module_cmd(loader_ctx *lctx, module_t *mod)
{
    if (LOADER_CTX_BAD(lctx) || mod == NULL)
        return NULL;

    if (lctx->type == MB1_ONLY)
        return (char *) mod->string;
    else /* currently must be type 2 */
        return (char *)&(mod->string);
}

char *get_cmdline(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return NULL;

    if (lctx->type == MB1_ONLY){
        /* multiboot 1 */
        if (((multiboot_info_t *)lctx->addr)->flags & MBI_CMDLINE){
            return (char *) ((multiboot_info_t *)lctx->addr)->cmdline;
        } else {
            return NULL;
        }
    } else { 
        /* currently must be type  2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_CMDLINE);
        if (start != NULL){
            struct mb2_tag_string *cmd = (struct mb2_tag_string *) start;
            return (char *) &(cmd->string);
        }
        return NULL;
    }
}

int  have_loader_memlimits(loader_ctx *lctx)
{
	if (LOADER_CTX_BAD(lctx))
		return 0;
	if (lctx->type == MB1_ONLY) {
		return (((multiboot_info_t *)lctx->addr)->flags & MBI_MEMLIMITS) != 0;
	} else {
		out_info("We dont expect to be here : have_loader_memlimits");
		/* currently must be type 2 */
	}
	return 0;
}

uint32_t get_loader_mem_lower(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return ((multiboot_info_t *)lctx->addr)->mem_lower;
    }
    /* currently must be type 2 */
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MEMLIMITS);
    if (start != NULL){
        struct mb2_tag_memlimits *lim = (struct mb2_tag_memlimits *) start;
        return lim->mem_lower;
    }
    return 0;
}

uint32_t get_loader_mem_upper(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return ((multiboot_info_t *)lctx->addr)->mem_upper;
    }
    /* currently must be type 2 */
    struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_MEMLIMITS);
    if (start != NULL){
        struct mb2_tag_memlimits *lim = (struct mb2_tag_memlimits *) start;
        return lim->mem_upper;
    }
    return 0;
}

unsigned int get_module_count(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == MB1_ONLY){
        return(((multiboot_info_t *) lctx->addr)->mods_count);
    } else {
        /* currently must be type 2 */
        struct mb2_tag *start = (struct mb2_tag *)(lctx->addr + 8);
        unsigned int count = 0;
        start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
        while (start != NULL){
            count++;
            /* nudge off this guy */
            start = next_mb2_tag(start);
            start = find_mb2_tag_type(start, MB2_TAG_TYPE_MODULE);
        }
        return count;
    }
}

int have_loader_memmap(loader_ctx *lctx)
{
	if (LOADER_CTX_BAD(lctx))
		return 0;
	if (lctx->type == MB1_ONLY){
		return (((multiboot_info_t *) lctx->addr)->flags & MBI_MEMMAP) != 0;
	} else {
		out_info("We dont expect to be here: have_loader_memmap");
		while(1);
	}
	return 0;
}

memory_map_t *get_loader_memmap(loader_ctx *lctx)
{
	if (LOADER_CTX_BAD(lctx))
		return NULL;
	if (lctx->type == MB1_ONLY){
		/* multiboot 1 */
		return (memory_map_t *)((multiboot_info_t *) lctx->addr)->mmap_addr;
	} else {
		out_info("We dont expect to be here : get_loader_memmap");
		while(1);
	}
}
uint32_t get_loader_memmap_length(loader_ctx *lctx)
{
	if (LOADER_CTX_BAD(lctx))
		return 0;
	if (lctx->type == MB1_ONLY){
		/* multiboot 1 */
		return (uint32_t)((multiboot_info_t *) lctx->addr)->mmap_length;
	} else {
		out_info("We dont expect to be here : get_loader_memmap_length");
		return 0;
	}
}

unsigned long
get_loader_ctx_end(loader_ctx *lctx)
{
    if (LOADER_CTX_BAD(lctx))
        return 0;
    if (lctx->type == 1){
        /* multiboot 1 */
        return (get_mbi_mem_end_mb1((multiboot_info_t *) lctx->addr));
    } else {
        /* currently must be type 2 */
        unsigned long mb2_size = *((unsigned long *) lctx->addr);
        return PAGE_UP(mb2_size + (unsigned long) lctx->addr);
    }
}

void replace_e820_map(loader_ctx *lctx)
{
	/* replace original with the copy */
	if (LOADER_CTX_BAD(lctx)) {
		out_info("PROBLEM : CONTEXT structure not valide");
		return;
	}
	if (lctx->type == MB1_ONLY){
		/* multiboot 1 */
		multiboot_info_t *mbi = (multiboot_info_t *) lctx->addr;
		mbi->mmap_addr = (uint32_t)get_e820_copy();
		mbi->mmap_length = (get_nr_map()) * sizeof(memory_map_t);
		mbi->flags |= MBI_MEMMAP;   /* in case only MBI_MEMLIMITS was set */
		out_info("UPDATED E820 MAP with copy");
		return;
	} else {
		out_info("We are not suppose to be here");
		while(1);
	}
	return;
}

bool get_loader_efi_ptr(loader_ctx *lctx, uint32_t *address, uint64_t *long_address)
{
    struct mb2_tag *start, *hit;
    struct mb2_tag_efi32 *efi32;
    struct mb2_tag_efi64 *efi64;
    if (LOADER_CTX_BAD(lctx))
        return false;
    if (lctx->type != MB2_ONLY)
        return false;
    start = (struct mb2_tag *)(lctx->addr + 8);
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI32);
    if (hit != NULL){
        efi32 = (struct mb2_tag_efi32 *) hit;
        *address = (uint32_t) efi32->pointer;
        *long_address = 0;
        return true;
    }
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI64);
    if (hit != NULL){
        efi64 = (struct mb2_tag_efi64 *) hit;
        *long_address = (uint64_t) efi64->pointer;
        *address = 0;
        return true;
    }
    return false;
}


uint32_t find_efi_memmap(loader_ctx *lctx, uint32_t *descr_size,
                uint32_t *descr_vers, uint32_t *mmap_size) {
    struct mb2_tag *start = NULL, *hit = NULL;
    struct mb2_tag_efi_mmap *efi_mmap = NULL;

    start = (struct mb2_tag *)(lctx->addr + 8);
    hit = find_mb2_tag_type(start, MB2_TAG_TYPE_EFI_MMAP);
    if (hit == NULL) {
       return 0;
    }

    efi_mmap = (struct mb2_tag_efi_mmap *)hit;
    *descr_size = efi_mmap->descr_size;
    *descr_vers = efi_mmap->descr_vers;
    *mmap_size = efi_mmap->size;
    return (uint32_t)(&efi_mmap->efi_mmap); 
}

bool is_loader_launch_efi(loader_ctx *lctx)
{
    uint32_t addr = 0; uint64_t long_addr = 0;
    if (LOADER_CTX_BAD(lctx))
        return false;
    return (get_loader_efi_ptr(lctx, &addr, &long_addr));
}

void load_framebuffer_info(loader_ctx *lctx, void *vscr)
{
    screen_info_t *scr = (screen_info_t *) vscr;
    struct mb2_tag *start;

    if (scr == NULL)
        return;
    if (LOADER_CTX_BAD(lctx))
        return;
    start = (struct mb2_tag *)(lctx->addr + 8);
    start = find_mb2_tag_type(start, MB2_TAG_TYPE_FRAMEBUFFER);
    if (start != NULL){
        struct mb2_fb *mbf = (struct mb2_fb *) start;
        scr->lfb_base = (uint32_t) mbf->common.fb_addr;
        scr->lfb_width = mbf->common.fb_width;
        scr->lfb_height = mbf->common.fb_height;
        scr->lfb_depth =  mbf->common.fb_bpp;
        scr->lfb_line_len = mbf->common.fb_pitch;
        scr->red_mask_size = mbf->fb_red_mask_size; 
        scr->red_field_pos = mbf->fb_red_field_position; 
        scr->blue_mask_size = mbf->fb_blue_mask_size; 
        scr->blue_field_pos = mbf->fb_blue_field_position; 
        scr->green_mask_size = mbf->fb_green_mask_size; 
        scr->green_field_pos = mbf->fb_green_field_position; 

        scr->lfb_size = scr->lfb_line_len * scr->lfb_height;
        /* round up to next 64k */
        scr->lfb_size = (scr->lfb_size + 65535) & 65535;
        
        scr->orig_video_isVGA = 0x70; /* EFI FB */
        scr->orig_y = 24;
    }

}
