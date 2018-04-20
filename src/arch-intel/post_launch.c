/*
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <config.h>
#include <types.h>
#include <util.h>
#include <uuid.h>
#include <loader.h>
#include <processor.h>
#include <io.h>
#include <mutex.h>
#include <intel_tpm.h>
#include <vmcs.h>
#include <txt.h>
#include <exception.h>
#include <mbi.h>
#include <e820.h>
#include <tboot.h>
#include <misc.h>
#include <atomic.h>
#include <keyboard.h>
#include <acpi.h>
#include <integrity.h>

typedef struct __packed {
    uint64_t  base;
    uint64_t  length;
    uint8_t   mem_type;
    uint8_t   reserved[7];
} sinit_mdr_t;
#include <verify.h>

extern loader_ctx *g_ldr_ctx;
RESULT post_launch(struct mbi *m);
extern tboot_shared_t _tboot_shared;
extern int save_vtd_dmar_table(void);
extern void print_e820_map(void);

#define PAGE_SHIFT       12                 /* LOG2(PAGE_SIZE) */
#define PAGE_SIZE        (1 << PAGE_SHIFT)  /* bytes/page */
/* PAGE_MASK is used to pass bits 12 and above. */
#define PAGE_MASK        (~(PAGE_SIZE-1))
#define PAGE_UP(p)   (((unsigned long)(p) + PAGE_SIZE- 1) & PAGE_MASK)
unsigned long get_tboot_mem_end(void)
{
    return PAGE_UP((unsigned long)&_end);
}

extern void _prot_to_real(uint32_t dist_addr);
extern void verify_all_modules(loader_ctx *lctx);
/* counter timeout for waiting for all APs to exit guests */
#define AP_GUEST_EXIT_TIMEOUT     0x01000000

extern long s3_flag;

extern char s3_wakeup_16[];
extern char s3_wakeup_end[];

extern atomic_t ap_wfs_count;

extern struct mutex ap_lock;

/*
 * caution: must make sure the total wakeup entry code length
 * (s3_wakeup_end - s3_wakeup_16) can fit into one page.
 */
static __data uint8_t g_saved_s3_wakeup_page[PAGE_SIZE];

static bool is_launched(void)
{
        return txt_is_launched();
}

static void copy_s3_wakeup_entry(void)
{
    if ( s3_wakeup_end - s3_wakeup_16 > PAGE_SIZE ) {
        out_info("S3 entry is too large to be copied into one page!\n");
        return;
    }

    /* backup target address space first */
    memcpy(g_saved_s3_wakeup_page, (void *)TBOOT_S3_WAKEUP_ADDR,
           s3_wakeup_end - s3_wakeup_16);

    /* copy s3 entry into target mem */
    memcpy((void *)TBOOT_S3_WAKEUP_ADDR, s3_wakeup_16,
           s3_wakeup_end - s3_wakeup_16);
}

extern void txt_post_launch(void);

void intel_post_launch(void){
	out_info("We are in post launch processing --  Measured launch succeeded");
	uint64_t base, size;
	extern void shutdown_entry(void);

	/* init MLE/kernel shared data page early, .num_in_wfs used in ap wakeup*/
	_tboot_shared.num_in_wfs = 0;
	txt_post_launch();
	/* Bhushan : I guess we can skip backing up DMAR. keeping it for now, will remove while master merge */
	/* backup DMAR table */
	save_vtd_dmar_table();

	/* remove all TXT sinit acm modules before verifying modules */
	remove_txt_modules(g_ldr_ctx);

	/*
	 * verify e820 table and adjust it to protect our memory regions
	 */

	/* marked mem regions used by TXT (heap, SINIT, etc.) as E820_RESERVED */
	int err = txt_protect_mem_regions();
	if(err)	{
		out_info("Error: txt_protect_mem_regions failed!\n");
	} else {
		out_info("txt_protect_mem_regions succeeded!\n");
	}

	/* ensure all modules are in RAM */
	if (!verify_modules(g_ldr_ctx) )	{
		out_info("Error: verify_modules failed!\n");
	} else {
		out_info("verify_modules succeeded!\n");
	}

	/* verify that tboot is in valid RAM (i.e. E820_RAM) */
	base = (uint64_t)TBOOT_BASE_ADDR;
	size = (uint64_t)((unsigned long)&_end - base);
	out_info("verifying tboot and its page table in e820 table\n\t");
	if ( e820_check_region(base, size) != E820_RAM ) {
		out_info(": failed.\n");
	} else {
		out_info(": succeeded.\n");
	}

	/* protect ourselves, MLE page table, and MLE/kernel shared page */
	base = (uint64_t)TBOOT_BASE_ADDR;
	size = (uint64_t)get_tboot_mem_end() - base;
	uint32_t mem_type = E820_RESERVED;
	out_info("protecting tboot in e820 table\n");
	if ( !e820_protect_region(base, size, mem_type) ){
		out_info("Error: e820_protect_region failed!\n");
	}else{
		out_info("e820_protect_region succeeded!\n");
	}

	/* replace map in loader context with copy */
	replace_e820_map(g_ldr_ctx);

	#ifndef NDEBUG
	out_info("adjusted e820 map:");
	print_e820_map();
	#endif

	/* Remove _tboot_shared : when we will remove linux kernel part */
	memset(&_tboot_shared, 0, PAGE_SIZE);
	_tboot_shared.uuid = (uuid_t)TBOOT_SHARED_UUID;
    	_tboot_shared.version = 6;
	_tboot_shared.shutdown_entry = (uint32_t)shutdown_entry;
	_tboot_shared.tboot_base = (uint32_t)&_start;
	_tboot_shared.tboot_size = (uint32_t)&_end - (uint32_t)&_start;
	_tboot_shared.num_in_wfs = atomic_read(&ap_wfs_count);
}

void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec)
{
	out_description("cpu waking up \n", cpuid);

	/* change to real mode and then jump to SIPI vector */
	_prot_to_real(sipi_vec);
}


static void shutdown_system(uint32_t shutdown_type)
{
	switch( shutdown_type ) {
		case TB_SHUTDOWN_S3:
			copy_s3_wakeup_entry();
			/* write our S3 resume vector to ACPI resume addr */
			set_s3_resume_vector(&_tboot_shared.acpi_sinfo,  TBOOT_S3_WAKEUP_ADDR);
			/* fall through for rest of Sx handling */
			/* FALLTHROUGH */
		case TB_SHUTDOWN_S4:
		case TB_SHUTDOWN_S5:
			machine_sleep(&_tboot_shared.acpi_sinfo);
			/* if machine_sleep() fails, fall through to reset */

		/* FALLTHROUGH */
		case TB_SHUTDOWN_REBOOT:
			if ( txt_is_powercycle_required() ) {
				/* powercycle by writing 0x0a+0x0e to port 0xcf9 */
				/* (supported by all TXT-capable chipsets) */
				outb(0xcf9, 0x0a);
				outb(0xcf9, 0x0e);
			} else {
				/* soft reset by writing 0xfe to keyboard reset vector 0x64 */
				/* BIOSes (that are not performing some special operation, */
				/* such as update) will turn this into a platform reset as */
				/* expected. */
				outb(0x64, 0xfe);
				/* fall back to soft reset by writing 0x06 to port 0xcf9 */
				/* (supported by all TXT-capable chipsets) */
				outb(0xcf9, 0x06);
			}

		/* FALLTHROUGH */
		case TB_SHUTDOWN_HALT:
		default:
			while (true)
				halt();
	}
}

void shutdown(void)
{
	/* wait-for-sipi only invoked for APs, so skip all BSP shutdown code */
	if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_WFS ) {
		atomic_inc(&ap_wfs_count);
		_tboot_shared.ap_wake_trigger = 0;
		//mtx_enter(&ap_lock);
		out_info("shutdown(): TB_SHUTDOWN_WFS\n");
		if (use_mwait())
			ap_wait(get_apicid());
		else
			handle_init_sipi_sipi(get_apicid());
	}

	out_info("wait until all APs ready for txt shutdown\n");
	while( atomic_read(&_tboot_shared.num_in_wfs) < atomic_read(&ap_wfs_count) )
		cpu_relax();

	/* ensure localities 0, 1 are inactive (in case kernel used them) */
	/* request TPM current locality to be active */
	
	if ( _tboot_shared.shutdown_type == TB_SHUTDOWN_S3 ) {
		/* restore DMAR table if needed */
		restore_vtd_dmar_table();

		/* save kernel/VMM resume vector for sealing */
		g_post_k_s3_state.kernel_s3_resume_vector =  _tboot_shared.acpi_sinfo.kernel_s3_resume_vector;

		/* create and seal memory integrity measurement */
		/*
		 * Bhushan: We can remove this memset but need more investigation
		 */
		memset(_tboot_shared.s3_key, 0, sizeof(_tboot_shared.s3_key));
	}

	/* cap dynamic PCRs extended as part of launch (17, 18, ...) */
	if (is_launched()) {
		/* scrub any secrets by clearing their memory, then flush cache */
		/* we don't have any secrets to scrub, however */
		/* in mwait "mode", APs will be in MONITOR/MWAIT and can be left there */
		if ( !use_mwait() ) {
			/* force APs to exit mini-guests if any are in and wait until */
			/* all are out before shutting down TXT */
			out_info("waiting for APs to exit guests...\n");
			force_aps_exit();
			uint32_t timeout = AP_GUEST_EXIT_TIMEOUT;
			do {
				if ( timeout % 0x8000 == 0 )
					out_info(".");
				else
					cpu_relax();
				if ( timeout % 0x200000 == 0 )
					out_info("\n");
				timeout--;
			} while ( ( atomic_read(&ap_wfs_count) > 0 ) && timeout > 0 );
			out_info("\n");
			if ( timeout == 0 )
				out_info("AP guest exit loop timed-out\n");
			else
				out_info("all APs exited guests\n");
		} else {
			/* reset ap_wfs_count to avoid tboot hash changing in S3 case */
			atomic_set(&ap_wfs_count, 0);
		}

		/* turn off TXT (GETSEC[SEXIT]) */
		txt_shutdown();
	}

	/* machine shutdown */
	shutdown_system(_tboot_shared.shutdown_type);
}

void handle_exception(void)
{
	out_info("received exception; shutting down...\n");
	_tboot_shared.shutdown_type = TB_SHUTDOWN_REBOOT;
	shutdown();
}
