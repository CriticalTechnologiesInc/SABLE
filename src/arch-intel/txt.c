#include "types.h"
#include "smx.h"
#include "processor.h"
#include "util.h"
#include "config_regs.h"
#include "msr.h"
#include "uuid.h"
#include "config.h"
#include "mle.h"
#include "acmod.h"
#include "page.h"
#include "mtrrs.h"
#include "intel_tpm.h"
#include "arch-intel/heap.h"
#include "tboot.h"
#include "acpi.h"
#include "atomic.h"
#include "keyboard.h"
#include "mutex.h"
#include <multiboot.h>
#include <loader.h>
#include <verify.h>
#include <e820.h>
#include <vmcs.h>

#define ACM_MEM_TYPE_UC                 0x0100
#define ACM_MEM_TYPE_WC                 0x0200
#define ACM_MEM_TYPE_WT                 0x1000
#define ACM_MEM_TYPE_WP                 0x2000
#define ACM_MEM_TYPE_WB                 0x4000
 
#define DEF_ACM_MAX_SIZE                0x8000
#define DEF_ACM_VER_MASK                0xffffffff
#define DEF_ACM_VER_SUPPORTED           0x00
#define DEF_ACM_MEM_TYPES               ACM_MEM_TYPE_UC
#define DEF_SENTER_CTRLS                0x00
 
extern acm_hdr_t *g_sinit;

struct cpu_state {
	unsigned long eax, ebx, ecx, edx, edi, esi;
	uint16_t cs, ds, es, fs, gs, ss;
	unsigned long efer, eflags, esp, ebp;
 	unsigned long cr0, cr2, cr3, cr4;

 	/* idt, gdt actually 48 bits each */
 	uint16_t gdt_pad;
 	uint16_t gdt_limit;
 	unsigned long gdt_base;
 	uint16_t idt_pad;
 	uint16_t idt_limit;
 	unsigned long idt_base;
 	uint16_t ldt;
 	uint16_t tss;
	unsigned long tr;
 	unsigned long safety;
 	unsigned long return_address;
 	/* used for storing timing information across PAL invocations */
 	unsigned long startl, starth, endl, endh;
	/* add this to physical base addr to get same addr in kernel virt space */
	unsigned long p2v_offset;
} __attribute__((packed));

typedef struct cpu_state cpu_t;


/**
 * Dump saved processor state to debug output
 */

void dump_state(cpu_t *s) {
	if(s == NULL) { return; }

	out_description("eax", s->eax);
	out_description("ebx", s->ebx);
	out_description("ecx", s->ecx);
	out_description("edx", s->edx);
	out_description("edi", s->edi);
	out_description("esi", s->esi);

	out_description("cs", s->cs);
	out_description("ds", s->ds);
	out_description("es", s->es);
	out_description("fs", s->fs);
	out_description("gs", s->gs);
	out_description("ss", s->ss);


	out_description("eflags", s->eflags);
	out_description("efer", s->efer);
	out_description("esp", s->esp);
	out_description("ebp", s->ebp);


	out_description("cr0", s->cr0);
	out_description("cr2", s->cr2);
	out_description("cr3", s->cr3);
	out_description("cr4", s->cr4);
 
	out_description("gdt base", s->gdt_base);
	out_description("gdt limit", s->gdt_limit);
	out_description("idt base", s->idt_base);
	out_description("idt limit", s->idt_limit);
 
	out_description("ldt", s->ldt);
	out_description("tss", s->tss);
	out_description("tr", s->tr);
	out_description("safety", s->safety);
	out_description("return add", s->return_address);

	out_description("return add", s->ebp);
	out_description("return add", s->esp);
}

void print_cpu_state() {
	out_description("EFlags", read_eflags());
	out_description64("EFlags", read_eflags());
	out_description64("ECX", read_ecx());
	out_description64("CR0", read_cr0());
	out_description64("CR4", read_cr4());
	out_description64("CR3", read_cr3());
}

int get_parameters(getsec_parameters_t *params)
{
	unsigned long cr4;
	uint32_t index, eax, ebx, ecx;
	int param_type;


	// START 
	// this code is placed here to avoid SMX not enabled error and should be removed once
	// testing is done for loading SINIT module

	/* testing for chipset support requires enabling SMX on the processor */
	write_cr4(read_cr4() | CR4_SMXE);
	out_info("Remove this code : SMX is enabled"); // TODO ??

	// END

	/* sanity check because GETSEC[PARAMETERS] will fail if not set */
	cr4 = read_cr4();
	if ( !(cr4 & CR4_SMXE) ) {
		out_info("SMXE not enabled, can't read parameters");
		return 0;
	}

	memset(params, 0, sizeof(*params));
	params->acm_max_size = DEF_ACM_MAX_SIZE;
	params->acm_mem_types = DEF_ACM_MEM_TYPES;
	params->senter_controls = DEF_SENTER_CTRLS;
	params->proc_based_scrtm = 0;
	params->preserve_mce = 0;

	index = 0;
	do {
		__getsec_parameters(index++, &param_type, &eax, &ebx, &ecx);

		/* the code generated for a 'switch' statement doesn't work in this */
		/* environment, so use if/else blocks instead */

		/* NULL - all reserved */
		if (param_type == 0)
		;
		/* supported ACM versions */
		else if (param_type == 1) {
			if (params->n_versions == MAX_SUPPORTED_ACM_VERSIONS )
				out_info("number of supported ACM version exceeds MAX_SUPPORTED_ACM_VERSIONS");
			else {
				params->acm_versions[params->n_versions].mask = ebx;
				params->acm_versions[params->n_versions].version = ecx;
				params->n_versions++;
			}
		}
		/* max size AC execution area */
		else if (param_type == 2)
			params->acm_max_size = eax & 0xffffffe0;
		/* supported non-AC mem types */
		else if (param_type == 3)
			params->acm_mem_types = eax & 0xffffffe0;
		/* SENTER controls */
		else if (param_type == 4)
			params->senter_controls = (eax & 0x00007fff) >> 8;
		/* TXT extensions support */
		else if (param_type == 5) {
			params->proc_based_scrtm = (eax & 0x00000020) ? 1 : 0;
			params->preserve_mce = (eax & 0x00000040) ? 1 : 0;
		}else {
			out_description("unknown GETSEC[PARAMETERS] type", param_type);
			param_type = 0;    /* set so that we break out of the loop */
		}

	} while (param_type != 0);

		if (params->n_versions == 0) {
			params->acm_versions[0].mask = DEF_ACM_VER_MASK;
			params->acm_versions[0].version = DEF_ACM_VER_SUPPORTED;
			params->n_versions = 1;
		}

	return 1;
}
/* counter timeout for waiting for all APs to enter wait-for-sipi */
#define AP_WFS_TIMEOUT     0x10000000

__data struct acpi_rsdp g_rsdp;
extern char __start[];		/* start of module */
extern char _end[];		/* end of module */
extern char _mle_start[];	/* start of text section */
extern char _mle_end[];		/* end of text section */
extern char _skinit[];		/* entry point post SENTER, in boot.S */
extern char _txt_wakeup[];        /* RLP join address for GETSEC[WAKEUP] */



/*
 * Bhushan : I think g_cmdline is not needed for sable but 
 * keeping it as a placeholder. we can remove it later
 * copy of original command line
 * part of tboot measurement (hence in .text section)
 */

#define CMDLINE_SIZE	512
extern char g_cmdline[CMDLINE_SIZE];

extern struct mutex ap_lock;
/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;
extern void cpu_wakeup(uint32_t cpuid, uint32_t sipi_vec);

/*
 * this is the structure whose addr we'll put in TXT heap
 * it needs to be within the MLE pages, so force it to the .text section
 */

/* 
 * Bhushan : 
 * we need to replace &_skinit with &_post_launch_entry once its implementation ready
 */

static __text const mle_hdr_t g_mle_hdr = {
	uuid			:	MLE_HDR_UUID,
	length			:	sizeof(mle_hdr_t),
	version			:	MLE_HDR_VER,
	entry_point		:	(uint32_t)&_skinit - TBOOT_START,
	first_valid_page	:	0,
	mle_start_off		:	(uint32_t)&_mle_start - TBOOT_BASE_ADDR,
	mle_end_off		:	(uint32_t)&_mle_end - TBOOT_BASE_ADDR,
	capabilities		:	{ MLE_HDR_CAPS },
	cmdline_start_off	:	(uint32_t)g_cmdline - TBOOT_BASE_ADDR,
	cmdline_end_off		:	(uint32_t)g_cmdline + CMDLINE_SIZE - 1 - TBOOT_BASE_ADDR,
};


/*
 * counts of APs going into wait-for-sipi
 */
/* count of APs in WAIT-FOR-SIPI */

atomic_t ap_wfs_count;
static void print_file_info(void)
{
	out_info("file addresses:");
	out_description("&_start=", (unsigned int)&__start);
	out_description("&_end=", (unsigned int)&_end);
	out_description("&_mle_start=", (unsigned int)&_mle_start);
	out_description("&_mle_end=", (unsigned int)&_mle_end);
	out_description("&_post_launch_entry=", (unsigned int)&_skinit);
	out_description("&_txt_wakeup=", (unsigned int)&_txt_wakeup);
	out_description("&g_mle_hdr=", (unsigned int)&g_mle_hdr);
}

static void print_mle_hdr(const mle_hdr_t *mle_hdr)
{
	out_info("MLE header:");
	out_info("uuid=");
	print_uuid(&mle_hdr->uuid); 
	out_description("length :", mle_hdr->length);
	out_description("version :", mle_hdr->version);
	out_description("entry_point :", mle_hdr->entry_point);
	out_description("first_valid_page :", mle_hdr->first_valid_page);
	out_description("mle_start_off :", mle_hdr->mle_start_off);
	out_description("mle_end_off :", mle_hdr->mle_end_off);
	print_txt_caps(mle_hdr->capabilities);
}

/*
 * build_mle_pagetable()
 */

/* page dir/table entry is phys addr + P + R/W + PWT */
#define MAKE_PDTE(addr)  (((uint64_t)(unsigned long)(addr) & PAGE_MASK) | 0x01)

/* we assume/know that our image is <2MB and thus fits w/in a single */
/* PT (512*4KB = 2MB) and thus fixed to 1 pg dir ptr and 1 pgdir and */
/* 1 ptable = 3 pages and just 1 loop loop for ptable MLE page table */
/* can only contain 4k pages */

static __mlept uint8_t g_mle_pt[3 * PAGE_SIZE];  
/* pgdir ptr + pgdir + ptab = 3 */

static void *build_mle_pagetable(uint32_t mle_start, uint32_t mle_size)
{
	void *ptab_base;
	uint32_t ptab_size, mle_off;
	void *pg_dir_ptr_tab, *pg_dir, *pg_tab;
	uint64_t *pte;

	#ifndef NDEBUG
	out_info("MLE information : Creating pages for MLE");
	out_description("Start", mle_start);
	out_description("End", mle_start + mle_size);
	out_description("Size", mle_size);
	#endif

	if (mle_size > 512 * PAGE_SIZE ) {
		out_info("MLE size too big for single page table");
		return NULL;
	}

	/* should start on page boundary */
	if (mle_start & ~PAGE_MASK) {
		out_info("MLE start is not page-aligned");
		return NULL;
	}

	/* place ptab_base below MLE */
	ptab_size = sizeof(g_mle_pt);
	ptab_base = &g_mle_pt;
	memset(ptab_base, 0, ptab_size);

	#ifndef NDEBUG
	out_info("Page table information");
	out_description("ptab_size=", ptab_size);
	out_description("ptab_base=", (unsigned int)ptab_base);
	#endif

	pg_dir_ptr_tab	= ptab_base;
	pg_dir		= pg_dir_ptr_tab + PAGE_SIZE;
	pg_tab		= pg_dir + PAGE_SIZE;


	/* only use first entry in page dir ptr table */
	*(uint64_t *)pg_dir_ptr_tab = MAKE_PDTE(pg_dir);

	/* only use first entry in page dir */
	*(uint64_t *)pg_dir = MAKE_PDTE(pg_tab);

	pte = pg_tab;
	mle_off = 0;
	do {
		*pte = MAKE_PDTE(mle_start + mle_off);
		pte++;
		mle_off += PAGE_SIZE;
	} while (mle_off < mle_size);

	return ptab_base;
}


static __data event_log_container_t *g_elog = NULL;

/* should be called after os_mle_data initialized */
static void *init_event_log(void) // TODO is this used?
{
	os_mle_data_t *os_mle_data = get_os_mle_data_start(get_txt_heap());
	g_elog = (event_log_container_t *)&os_mle_data->event_log_buffer;

	memcpy((void *)g_elog->signature, EVTLOG_SIGNATURE, sizeof(g_elog->signature));
	g_elog->container_ver_major = EVTLOG_CNTNR_MAJOR_VER;
	g_elog->container_ver_minor = EVTLOG_CNTNR_MINOR_VER;
	g_elog->pcr_event_ver_major = EVTLOG_EVT_MAJOR_VER;
	g_elog->pcr_event_ver_minor = EVTLOG_EVT_MINOR_VER;
	g_elog->size = sizeof(os_mle_data->event_log_buffer);
	g_elog->pcr_events_offset = sizeof(*g_elog);
	g_elog->next_event_offset = sizeof(*g_elog);

	return (void *)g_elog;
}

static void init_os_sinit_ext_data(heap_ext_data_element_t* elts)
{
	heap_event_log_ptr_elt_t*	evt_log;
	heap_ext_data_element_t*	elt = elts;

//	if (g_tpm->major == TPM12_VER_MAJOR) {
		evt_log = (heap_event_log_ptr_elt_t *)elt->data;
		evt_log->event_log_phys_addr = (uint64_t)(unsigned long)init_event_log();
		elt->type = HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR;
		elt->size = sizeof(*elt) + sizeof(*evt_log);
//	} else if ( g_tpm->major == TPM20_VER_MAJOR ) {
//		out_info("We dont expect to be here: init_os_sinit_ext_data");
//		while(1);
//	}
	elt = (void *)elt + elt->size;
	elt->type = HEAP_EXTDATA_TYPE_END;
	elt->size = sizeof(*elt);
}

__data uint32_t g_using_da = 0;

/*
 * sets up TXT heap
 */

void set_vtd_pmrs(os_sinit_data_t *os_sinit_data, uint64_t min_lo_ram, uint64_t max_lo_ram, uint64_t min_hi_ram, uint64_t max_hi_ram){    
	#ifndef NDEBUG
	out_description64("min_lo_ram", min_lo_ram);
	out_description64("max_lo_ram", max_lo_ram);
	out_description64("min_hi_ram", min_hi_ram);
	out_description64("max_hi_ram", max_hi_ram);
	#endif

	/*
	 * base must be 2M-aligned and size must be multiple of 2M
	 * (so round bases and sizes down--rounding size up might conflict
	 * with a BIOS-reserved region and cause problems; in practice, rounding
	 * base down doesn't)
	 * we want to protect all of usable mem so that any kernel allocations
	 * before VT-d remapping is enabled are protected
	 */

	min_lo_ram &= ~0x1fffffULL;
	uint64_t lo_size = (max_lo_ram - min_lo_ram) & ~0x1fffffULL;
	os_sinit_data->vtd_pmr_lo_base = min_lo_ram;
	os_sinit_data->vtd_pmr_lo_size = lo_size;

	min_hi_ram &= ~0x1fffffULL;
	uint64_t hi_size = (max_hi_ram - min_hi_ram) & ~0x1fffffULL;
	os_sinit_data->vtd_pmr_hi_base = min_hi_ram;
	os_sinit_data->vtd_pmr_hi_size = hi_size;
}

static txt_heap_t *init_txt_heap(void *ptab_base, acm_hdr_t *sinit)
{
	txt_heap_t *txt_heap;
	uint64_t *size;

	txt_heap = get_txt_heap();

	/*
	 * BIOS data already setup by BIOS
	*/
	if (!verify_txt_heap(txt_heap, 1)) {
		return NULL;
		out_info("EORROR : bios_data init has some problem");
		while(1);
	}

	/*
	 * OS/loader to MLE data
	*/

	os_mle_data_t *os_mle_data = get_os_mle_data_start(txt_heap);
	size = (uint64_t *)((uint32_t)os_mle_data - sizeof(uint64_t));
	*size = sizeof(*os_mle_data) + sizeof(uint64_t);
	memset(os_mle_data, 0, sizeof(*os_mle_data));
	os_mle_data->version = 3;

	/*
	 * Bhushan: os_mle_data is vendor specific.
	 * we can store/initialize whatever value we want.
	 * Make sure to calculate value accordinly.
	 */

	// os_mle_data->lctx_addr = lctx->addr;
	os_mle_data->lctx_addr = NULL;
	os_mle_data->saved_misc_enable_msr = rdmsr(MSR_IA32_MISC_ENABLE);

	/*
	 * OS/loader to SINIT data
	 */
	/* check sinit supported os_sinit_data version */
	uint32_t version = get_supported_os_sinit_data_ver(sinit);
	if (version < MIN_OS_SINIT_DATA_VER) {
		out_description("ERROR: unsupported OS to SINIT data version in sinit", version);
		return NULL;
	}
	if (version > MAX_OS_SINIT_DATA_VER) {
		version = MAX_OS_SINIT_DATA_VER;
	}

	#ifndef NDEBUG
	out_description("OS to SINIT data version in sinit", version);
	#endif

	os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);
	size = (uint64_t *)((uint32_t)os_sinit_data - sizeof(uint64_t));
	*size = calc_os_sinit_data_size(version);
	memset(os_sinit_data, 0, *size);
	os_sinit_data->version = version;

	/* this is phys addr */
	os_sinit_data->mle_ptab = (uint64_t)(unsigned long)ptab_base;
	os_sinit_data->mle_size = g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off;
	/* this is linear addr (offset from MLE base) of mle header */
	os_sinit_data->mle_hdr_base = (uint64_t)(unsigned long)&g_mle_hdr - (uint64_t)(unsigned long)&_mle_start;
	/* VT-d PMRs */
	uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;

	if (!get_ram_ranges(&min_lo_ram, &max_lo_ram, &min_hi_ram, &max_hi_ram)) {
		return NULL;
	}

	set_vtd_pmrs(os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram);

	/* capabilities : choose monitor wake mechanism first */
	txt_caps_t sinit_caps = get_sinit_capabilities(sinit);
	txt_caps_t caps_mask = { 0 };
	caps_mask.rlp_wake_getsec = 1;
	caps_mask.rlp_wake_monitor = 1;
	caps_mask.pcr_map_da = 1;
	os_sinit_data->capabilities._raw = MLE_HDR_CAPS & ~caps_mask._raw;
	if (sinit_caps.rlp_wake_monitor)
		os_sinit_data->capabilities.rlp_wake_monitor = 1;
	else if (sinit_caps.rlp_wake_getsec)
		os_sinit_data->capabilities.rlp_wake_getsec = 1;
	else {     /* should have been detected in verify_acmod() */
		out_description("SINIT capabilities are incompatible", sinit_caps._raw);
		return NULL;
	}
 
	if (sinit_caps.tcg_event_log_format) {
		out_description("SINIT ACM supports TCG compliant TPM 2.0 event log format, tcg_event_log_format", sinit_caps.tcg_event_log_format);
		os_sinit_data->capabilities.tcg_event_log_format = 1;
	}

	/* capabilities : require MLE pagetable in ECX on launch */
	/* TODO: when SINIT ready
	 * os_sinit_data->capabilities.ecx_pgtbl = 1;
	 */

	os_sinit_data->capabilities.ecx_pgtbl = 0;
	/* we were launched EFI, set efi_rsdt_ptr */
	struct acpi_rsdp *rsdp = get_rsdp();
	if (rsdp != NULL){
		if (version < 6){
			/* rsdt */
			/* NOTE: Winston Wang says this doesn't work for v5 */
			os_sinit_data->efi_rsdt_ptr = (uint64_t) rsdp->rsdp1.rsdt;
		} else {
			/* rsdp */
			memcpy((void *)&g_rsdp, rsdp, sizeof(struct acpi_rsdp));
			os_sinit_data->efi_rsdt_ptr = (uint64_t)((uint32_t)&g_rsdp);
		}
	} else {
		/* per discussions--if we don't have an ACPI pointer, die */
		out_info("ERROR: Failed to find RSDP for EFI launch\n");
		while(1);
		return NULL;
	}

	/* capabilities : choose DA/LG */
	os_sinit_data->capabilities.pcr_map_no_legacy = 1;
	if(sinit_caps.pcr_map_da && 0 ) //&& get_tboot_prefer_da())
		os_sinit_data->capabilities.pcr_map_da = 1;
	else if ( !sinit_caps.pcr_map_no_legacy )
		os_sinit_data->capabilities.pcr_map_no_legacy = 0;
	else if ( sinit_caps.pcr_map_da ) {
		out_info("DA is the only supported PCR mapping by SINIT, use it");
		os_sinit_data->capabilities.pcr_map_da = 1;
	} else {
		out_description("SINIT capabilities are incompatible ", sinit_caps._raw);
		return NULL;
	}
	g_using_da = os_sinit_data->capabilities.pcr_map_da;

	/* 
	 * PCR mapping selection MUST be zero in TPM2.0 mode
	 * since D/A mapping is the only supported by TPM2.0
	 */

//	if ( g_tpm->major >= TPM20_VER_MAJOR ) {
//
//		/*
//		 * Bhushan :  assumption : we know our development environment is TPM 1.2
//		 */
//
//		out_info("ERROR: we dont expect to here");
//		while(1);
//	}   

	/* Event log initialization */

	if (os_sinit_data->version >= 6)
		init_os_sinit_ext_data(os_sinit_data->ext_data_elts);
	print_os_sinit_data(os_sinit_data);

	/*
	 * SINIT to MLE data will be setup by SINIT
	 */

	return txt_heap;
}

/* lock that protects APs against race conditions on wakeup and shutdown */
static void txt_wakeup_cpus(void)
{
	uint16_t cs;
	mle_join_t mle_join;
	unsigned int ap_wakeup_count;

	/*
	 * enable SMIs on BSP before waking APs (which will enable them on APs)
	 * because some SMM may take immediate SMI and hang if AP gets in first
	 */

	#ifndef NDEBUG
	out_info("enabling SMIs on BSP");
	#endif

	__getsec_smctrl();

	atomic_set(&ap_wfs_count, 0);

	/* RLPs will use our GDT and CS */
	extern char gdt[], end_gdt[];
	__asm__ __volatile__ ("mov %%cs, %0\n" : "=r"(cs));

	mle_join.entry_point = (uint32_t)(unsigned long)&_txt_wakeup;
	mle_join.seg_sel = cs;

	mle_join.gdt_base = (uint32_t) gdt;
	mle_join.gdt_limit = end_gdt - gdt - 1;

	#ifndef NDEBUG
	out_description("mle_join.entry_point ", (unsigned int)mle_join.entry_point);
	out_description("mle_join.seg_sel ", mle_join.seg_sel);
	out_description("mle_join.gdt_base ", mle_join.gdt_base);
	out_description("mle_join.gdt_limit ", mle_join.gdt_limit);
	#endif

	write_priv_config_reg(TXTCR_MLE_JOIN, (uint64_t)(unsigned long)&mle_join);

	mtx_init(&ap_lock);

	txt_heap_t *txt_heap = get_txt_heap();
	sinit_mle_data_t *sinit_mle_data = get_sinit_mle_data_start(txt_heap);
	os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);

      /* choose wakeup mechanism based on capabilities used */
	if (os_sinit_data->capabilities.rlp_wake_monitor) {
		#ifndef NDEBUG
		out_info("joining RLPs to MLE with MONITOR wakeup");
		out_description("rlp_wakeup_addr ", sinit_mle_data->rlp_wakeup_addr);
		WAIT_FOR_INPUT();
		#endif

		*((uint32_t *)(unsigned long)(sinit_mle_data->rlp_wakeup_addr)) = 0x01;
	}
	else {
		#ifndef NDEBUG
		out_info("joining RLPs to MLE with GETSEC[WAKEUP]");
		#endif
		__getsec_wakeup();
		#ifndef NDEBUG
		out_info("GETSEC[WAKEUP] completed");
                WAIT_FOR_INPUT();
		#endif
	}

	/* assume BIOS isn't lying to us about # CPUs, else some CPUS may not */
	/* have entered wait-for-sipi before we launch *or* we have to wait */
	/* for timeout before launching */
	/* (all TXT-capable CPUs have at least 2 cores) */

	bios_data_t *bios_data = get_bios_data_start(txt_heap);
	ap_wakeup_count = bios_data->num_logical_procs - 1;
	if ( ap_wakeup_count >= NR_CPUS ) {
		out_description("there are too many CPUs ", ap_wakeup_count);
		ap_wakeup_count = NR_CPUS - 1;
	}

	out_description("waiting for all APs to enter wait-for-sipi... count : ", ap_wakeup_count);
	/* wait for all APs that woke up to have entered wait-for-sipi */
	uint32_t timeout = AP_WFS_TIMEOUT;
	out_description("Timeout = ", timeout);
	do {
		if (timeout % 0x8000 == 0){
			out_info(".");
		}else{
			cpu_relax();
		}
		if (timeout % 0x200000 == 0)
		{
			out_description("ap_wfs_count = ",atomic_read(&ap_wfs_count));
			out_description("timeout = ",timeout);
//			WAIT_FOR_INPUT();
//			wait(500);
			out_info("\n");
		}
		timeout--;
	} while ((atomic_read(&ap_wfs_count) < ap_wakeup_count) && timeout > 0);
	out_info("\n");
	if (timeout == 0){
		out_info("wait-for-sipi loop timed-out");
	}else{
		out_info("all APs in wait-for-sipi");
		WAIT_FOR_INPUT();
	}
}

int txt_is_launched(void)
{
	txt_sts_t sts;

	sts._raw = read_pub_config_reg(TXTCR_STS);

	return sts.senter_done_sts;
}

int txt_launch_environment()
{
	void	*mle_ptab_base;
	os_mle_data_t *os_mle_data;
	txt_heap_t *txt_heap;

	/* print some debug info */
	print_file_info();
	print_mle_hdr(&g_mle_hdr);
	/* create MLE page table */
	mle_ptab_base = build_mle_pagetable(g_mle_hdr.mle_start_off + TBOOT_BASE_ADDR, g_mle_hdr.mle_end_off - g_mle_hdr.mle_start_off);
	if (mle_ptab_base == NULL) {
		out_info("Failed to create pages");
		return 0;
	}

	#ifndef NDEBUG
	out_info("Initializing Heap .....");
	#endif

	/* initialize TXT heap */
	txt_heap = init_txt_heap(mle_ptab_base, g_sinit);
	if (txt_heap == NULL) {
		out_info("Failed to initialize heap");
		return 0;
	}

	/* save MTRRs before we alter them for SINIT launch */
	os_mle_data = get_os_mle_data_start(txt_heap);
	save_mtrrs(&(os_mle_data->saved_mtrr_state));

	/* set MTRRs properly for AC module (SINIT) */
	if (!set_mtrrs_for_acmod(g_sinit)) {
		out_info("seting MTRRs for SINIT ACM failed");
		while(1);
		return 0;
	}

//	/* deactivate current locality */
//	if (g_tpm_family == TPM_IF_20_CRB ) {
//		out_info("We dont expect to be here");
//		while(1);
//	}

	#ifndef NDEBUG
	out_info("executing GETSEC[SENTER]...\n");
	out_description("SINIT BASE BASE :", (unsigned int) g_sinit);
	out_description("SINIT SIZE :", (unsigned int) (g_sinit->size)*4);
	print_cpu_state();
        WAIT_FOR_INPUT();
	#endif

	__getsec_senter((uint32_t)g_sinit, (g_sinit->size)*4);
	out_info("ERROR--we should not get here!\n");
	return 0;
}

int txt_prepare_cpu(void){
	unsigned long eflags, cr0;
	uint64_t mcg_cap, mcg_stat;

	/* must be running at CPL 0 => this is implicit in even getting this far */
	/* since our bootstrap code loads a GDT, etc. */

	cr0 = read_cr0();

	/* must be in protected mode */
	if (!(cr0 & CR0_PE)) {
		out_info("ERR: not in protected mode\n");
		return 0;
	}

	/* cache must be enabled (CR0.CD = CR0.NW = 0) */
	if (cr0 & CR0_CD) {
		out_info("CR0.CD set\n");
		cr0 &= ~CR0_CD;
	}
	if ( cr0 & CR0_NW ) {
		out_info("CR0.NW set\n");
		cr0 &= ~CR0_NW;
	}

	/* native FPU error reporting must be enabled for proper */
	/* interaction behavior */
	if (!(cr0 & CR0_NE)) {
		out_info("CR0.NE not set\n");
		cr0 |= CR0_NE;
	}

	write_cr0(cr0);

	/* cannot be in virtual-8086 mode (EFLAGS.VM=1) */
	eflags = read_eflags();
	if (eflags & X86_EFLAGS_VM) {
		out_info("EFLAGS.VM set");
		write_eflags(eflags | ~X86_EFLAGS_VM);
	}

	#ifndef NDEBUG
	out_info("CR0 and EFLAGS OK");
	#endif

//	/*
//	 * verify that we're not already in a protected environment
//	 */

//	if (txt_is_launched()) {
//		out_info("already in protected environment");
//		return 0;
//	}

	/*
	 * verify all machine check status registers are clear (unless
	 * support preserving them)
	 */

	/* no machine check in progress (IA32_MCG_STATUS.MCIP=1) */
	mcg_stat = rdmsr(MSR_MCG_STATUS);
	if (mcg_stat & 0x04) {
		out_info("machine check in progress");
		return 0;
	}

	getsec_parameters_t params;
	if (!get_parameters(&params)) {
		out_info("get_parameters() failed\n");
		return 0;
	}

	/* check if all machine check regs are clear */
	mcg_cap = rdmsr(MSR_MCG_CAP);
	for (unsigned int i = 0; i < (mcg_cap & 0xff); i++) {
		mcg_stat = rdmsr(MSR_MC0_STATUS + 4*i);
		if (mcg_stat & (1ULL << 63)) {
			out_description("MCG[index] =", i);
			out_description("ERROR =", mcg_stat);
		if (!params.preserve_mce)
			return 0;
		}
	}

//	if (params.preserve_mce){
//		#ifndef NDEBUG
//		out_info("supports preserving machine check errors");
//		#endif
//	}else{
//		out_info("no machine check errors");
//	}

//	if (params.proc_based_scrtm){
//		#ifndef NDEBUG
//		out_info("CPU support processor-based S-CRTM");
//		#endif
//	}

//	/* all is well with the processor state */
//	#ifndef NDEBUG
//	out_info("CPU is ready for SENTER");
//	#endif

	return 1;
}

static int verify_saved_mtrrs(txt_heap_t *txt_heap)
{   
	os_mle_data_t *os_mle_data;
	os_mle_data = get_os_mle_data_start(txt_heap);

	return validate_mtrrs(&(os_mle_data->saved_mtrr_state));
}   

static int reserve_vtd_delta_mem(uint64_t min_lo_ram, uint64_t max_lo_ram, uint64_t min_hi_ram, uint64_t max_hi_ram)
{
	uint64_t base, length;
	(void)min_lo_ram; (void)min_hi_ram;/* portably suppress compiler warning */
 
	txt_heap_t* txt_heap = get_txt_heap();
	os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);
 
	if (max_lo_ram != (os_sinit_data->vtd_pmr_lo_base + os_sinit_data->vtd_pmr_lo_size) ) {
		base = os_sinit_data->vtd_pmr_lo_base + os_sinit_data->vtd_pmr_lo_size;
		length = max_lo_ram - base;

		#ifndef NDEBUG
		out_info("reserving memory  which was truncated for VT-d");
		out_description("base", base);
		out_description("base + length", base + length);
		#endif

		if (!e820_reserve_ram(base, length))
			return 0;
	}
	if (max_hi_ram != (os_sinit_data->vtd_pmr_hi_base + os_sinit_data->vtd_pmr_hi_size)) {
		base = os_sinit_data->vtd_pmr_hi_base + os_sinit_data->vtd_pmr_hi_size;
		length = max_hi_ram - base;

		#ifndef NDEBUG
		out_info("reserving memory  which was truncated for VT-d");
		out_description("base", base);
		out_description("base + length", base + length);
		#endif

		if (!e820_reserve_ram(base, length))
			return 0;
	}
 
	return 1;
}

static int verify_vtd_pmrs(txt_heap_t *txt_heap)
{
	os_sinit_data_t *os_sinit_data, tmp_os_sinit_data;
	uint64_t min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram;

	os_sinit_data = get_os_sinit_data_start(txt_heap);

	/*
	 * make sure the VT-d PMRs were actually set to cover what
	 * we expect
	 */
 
	/* calculate what they should have been */
	/* no e820 table on S3 resume, so use saved (sealed) values */

		if (!get_ram_ranges(&min_lo_ram, &max_lo_ram, &min_hi_ram, &max_hi_ram))
			return 0;
 
		/* if vtd_pmr_lo/hi sizes rounded to 2MB granularity are less than the
		   max_lo/hi_ram values determined from the e820 table, then we must
		   reserve the differences in e820 table so that unprotected memory is
		   not used by the kernel */

		if (!reserve_vtd_delta_mem(min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram) ) {
			out_info("failed to reserve VT-d PMR delta memory");
			return 0;
		}
 
	/* compare to current values */
	memset(&tmp_os_sinit_data, 0, sizeof(tmp_os_sinit_data));
	tmp_os_sinit_data.version = os_sinit_data->version;
	set_vtd_pmrs(&tmp_os_sinit_data, min_lo_ram, max_lo_ram, min_hi_ram, max_hi_ram);

	if ((tmp_os_sinit_data.vtd_pmr_lo_base != os_sinit_data->vtd_pmr_lo_base)
	    || (tmp_os_sinit_data.vtd_pmr_lo_size != os_sinit_data->vtd_pmr_lo_size)
	    || (tmp_os_sinit_data.vtd_pmr_hi_base != os_sinit_data->vtd_pmr_hi_base)
	    || (tmp_os_sinit_data.vtd_pmr_hi_size != os_sinit_data->vtd_pmr_hi_size) ) {
		out_info("OS to SINIT data VT-d PMR settings do not match");
			print_os_sinit_data(&tmp_os_sinit_data);
			print_os_sinit_data(os_sinit_data);
			return 0;
	}

	return 1;
}

int txt_post_launch_verify_platform(void)
{
	txt_heap_t *txt_heap;

	/*
	 * verify some of the heap structures
	 */

	txt_heap = get_txt_heap();


	if (!verify_txt_heap(txt_heap, 0))
		return 1;

	/* verify the saved MTRRs */
	if (!verify_saved_mtrrs(txt_heap))
		return 1;

	/* verify that VT-d PMRs were really set as required */
	if (!verify_vtd_pmrs(txt_heap)) 
		return 1;

	return 0;
}                        

void txt_post_launch(void)
{
	txt_heap_t *txt_heap;
	os_mle_data_t *os_mle_data;
	int err;

	/* verify MTRRs, VT-d settings, TXT heap, etc. */
	err = txt_post_launch_verify_platform();

	/* don't return the error yet, because we need to restore settings */
	if (err != 0) {
		out_info("failed to verify platform");
		while(1);
	}

	out_info("Platform verification done");

	/* get saved OS state (os_mvmm_data_t) from LT heap */
	txt_heap = get_txt_heap();
	os_mle_data = get_os_mle_data_start(txt_heap);

	/* clear error registers so that we start fresh */
	write_priv_config_reg(TXTCR_ERRORCODE, 0x00000000);
	write_priv_config_reg(TXTCR_ESTS, 0xffffffff);  /* write 1's to clear */

	/* bring RLPs into environment (do this before restoring MTRRs to ensure */
	/* SINIT area is mapped WB for MONITOR-based RLP wakeup) */

	#ifndef NDEBUG
	out_info("About to wakeup CPUs\n");
	#endif

	txt_wakeup_cpus();

	/* restore pre-SENTER IA32_MISC_ENABLE_MSR (no verification needed)
	   (do after AP wakeup so that if restored MSR has MWAIT clear it won't
	   prevent wakeup) */
	#ifndef NDEBUG
	out_description("saved IA32_MISC_ENABLE", os_mle_data->saved_misc_enable_msr);
	#endif

	wrmsr(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

	/* restore pre-SENTER MTRRs that were overwritten for SINIT launch */
	restore_mtrrs(&(os_mle_data->saved_mtrr_state));

	/* always set the TXT.CMD.SECRETS flag */
	write_priv_config_reg(TXTCR_CMD_SECRETS, 0x01);
	read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */

	#ifndef NDEBUG
	out_info("set TXT.CMD.SECRETS flag");
	#endif

	/* open TPM locality 1 */
	write_priv_config_reg(TXTCR_CMD_OPEN_LOCALITY1, 0x01);
	read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */

	#ifndef NDEBUG
	out_info("opened TPM locality 1\n");
	#endif
}

void ap_wait(unsigned int cpuid)
{
    if ( cpuid >= NR_CPUS ) {
        out_description("cpuid exceeds # supported CPUs", cpuid);
        mtx_leave(&ap_lock);
        return;
    }

    /* ensure MONITOR/MWAIT support is set */
    uint64_t misc;
    misc = rdmsr(MSR_IA32_MISC_ENABLE);
    misc |= MSR_IA32_MISC_ENABLE_MONITOR_FSM;
    wrmsr(MSR_IA32_MISC_ENABLE, misc);

    /* this is close enough to entering monitor/mwait loop, so inc counter */
    atomic_inc((atomic_t *)&_tboot_shared.num_in_wfs);
    mtx_leave(&ap_lock);

    #ifndef NDEBUG
    out_description("cpu mwait'ing", cpuid); // tips fedora
    #endif

    while ( _tboot_shared.ap_wake_trigger != cpuid ) {
        cpu_monitor(&_tboot_shared.ap_wake_trigger, 0, 0);
        mb();
        if ( _tboot_shared.ap_wake_trigger == cpuid )
            break;
        cpu_mwait(0, 0);
    }

    uint32_t sipi_vec = (uint32_t)_tboot_shared.ap_wake_addr;
    atomic_dec(&ap_wfs_count);
    atomic_dec((atomic_t *)&_tboot_shared.num_in_wfs);
    cpu_wakeup(cpuid, sipi_vec);
}

void txt_cpu_wakeup(void)
{
	txt_heap_t *txt_heap;
	os_mle_data_t *os_mle_data;
	uint64_t madt_apicbase, msr_apicbase;
	unsigned int cpuid = get_apicid();


	if (cpuid >= NR_CPUS) {
		out_description("cpuid exceeds # supported CPUs. id", cpuid);
		return;
	}

	mtx_enter(&ap_lock);


	int timeout = 50;
	while(cpuid-1 != atomic_read(&ap_wfs_count) && timeout > 0)
	{
		wait(100);
		timeout--;
	}
	if(timeout == 0)
	{
		while(cpuid-2 != atomic_read(&ap_wfs_count) && timeout > 0)
			wait(100);
	}


	#ifndef NDEBUG
	out_description("cpu waking up from TXT sleep :", cpuid);
	#endif

	/* restore LAPIC base address for AP */
	madt_apicbase = (uint64_t)get_madt_apic_base();
	if (madt_apicbase == 0) {
		out_info("not able to get apci base from MADT\n");
		return;
	}
	msr_apicbase = rdmsr(MSR_APICBASE);
	if (madt_apicbase != (msr_apicbase & ~0xFFFULL)) {
		out_description("cpu restore apic base to of ", cpuid);
		out_description64("to base", madt_apicbase);
		wrmsr(MSR_APICBASE, (msr_apicbase & 0xFFFULL) | madt_apicbase);
	}

	txt_heap = get_txt_heap();
	os_mle_data = get_os_mle_data_start(txt_heap);

	/* apply (validated) (pre-SENTER) MTRRs from BSP to each AP */
	restore_mtrrs(&(os_mle_data->saved_mtrr_state));

	/* restore pre-SENTER IA32_MISC_ENABLE_MSR */
	wrmsr(MSR_IA32_MISC_ENABLE, os_mle_data->saved_misc_enable_msr);

	/* enable SMIs */
	#ifndef NDEBUG
	out_description("enabling SMIs on cpu :", cpuid);
	#endif

	__getsec_smctrl();

	atomic_inc(&ap_wfs_count);
        if ( use_mwait() ){
	    #ifndef NDEBUG
            out_info("AP wait\n");
	    #endif
            ap_wait(cpuid);
        }else{
	    #ifndef NDEBUG
            out_info("Handle\n");
	    #endif
            handle_init_sipi_sipi(cpuid);
	}
}

int txt_protect_mem_regions(void){
    uint64_t base, size;

    /*
     * TXT has 2 regions of RAM that need to be reserved for use by only the
     * hypervisor; not even dom0 should have access:
     *   TXT heap, SINIT AC module
     */

    /* TXT heap */
    base = read_pub_config_reg(TXTCR_HEAP_BASE);
    size = read_pub_config_reg(TXTCR_HEAP_SIZE);

    #ifndef NDEBUG
    out_info("protecting TXT heap in e820 table\n");
    #endif

    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return -1;

    /* SINIT */
    base = read_pub_config_reg(TXTCR_SINIT_BASE);
    size = read_pub_config_reg(TXTCR_SINIT_SIZE);

    #ifndef NDEBUG
    out_info("protecting SINIT in e820 table\n");
    #endif

    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return -1;

    /* TXT private space */
    base = TXT_PRIV_CONFIG_REGS_BASE;
    size = TXT_CONFIG_REGS_SIZE;

    #ifndef NDEBUG
    out_info("protecting TXT Private Space in e820 table\n");
    #endif

    if ( !e820_protect_region(base, size, E820_RESERVED) )
        return -1;

    /* ensure that memory not marked as good RAM by the MDRs is RESERVED in
       the e820 table */
    txt_heap_t* txt_heap = get_txt_heap();
    sinit_mle_data_t *sinit_mle_data = get_sinit_mle_data_start(txt_heap);
    uint32_t num_mdrs = sinit_mle_data->num_mdrs;
    sinit_mdr_t *mdrs_base = (sinit_mdr_t *)(((void *)sinit_mle_data
                                              - sizeof(uint64_t)) +
                                             sinit_mle_data->mdrs_off);

    #ifndef NDEBUG
    out_info("verifying e820 table against SINIT MDRs: ");
    #endif

    if ( !verify_e820_map(mdrs_base, num_mdrs) ) {
        out_info("verification failed.\n");
        return -2;
    }
    out_info("verification succeeded.\n");

    return 0;
}

void txt_shutdown(void)
{
    unsigned long apicbase;

    /* shutdown shouldn't be called on APs, but if it is then just hlt */
    apicbase = rdmsr(MSR_APICBASE);
    if ( !(apicbase & APICBASE_BSP) ) {
        out_info("calling txt_shutdown on AP\n");
        while ( true )
            halt();
    }

    /* set TXT.CMD.NO-SECRETS flag (i.e. clear SECRETS flag) */
    write_priv_config_reg(TXTCR_CMD_NO_SECRETS, 0x01);
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    out_info("secrets flag cleared\n");

    /* unlock memory configuration */
    write_priv_config_reg(TXTCR_CMD_UNLOCK_MEM_CONFIG, 0x01);
    read_pub_config_reg(TXTCR_E2STS);    /* fence */
    out_info("memory configuration unlocked\n");

    /* if some APs are still in wait-for-sipi then SEXIT will hang */
    /* so TXT reset the platform instead, expect mwait case */
    if ( (!use_mwait()) && atomic_read(&ap_wfs_count) > 0 ) {
        out_info("exiting with some APs still in wait-for-sipi state");
        write_priv_config_reg(TXTCR_CMD_RESET, 0x01);
    }

    /* close TXT private config space */
    /* implicitly closes TPM localities 1 + 2 */
    read_priv_config_reg(TXTCR_E2STS);   /* fence */
    write_priv_config_reg(TXTCR_CMD_CLOSE_PRIVATE, 0x01);
    read_pub_config_reg(TXTCR_E2STS);    /* fence */
    out_info("private config space closed\n");

    /* SMXE may not be enabled any more, so set it to make sure */
    write_cr4(read_cr4() | CR4_SMXE);

    /* call GETSEC[SEXIT] */
    out_info("executing GETSEC[SEXIT]...\n");
    __getsec_sexit();
    out_info("measured environment torn down\n");
}

bool txt_is_powercycle_required(void)
{
    /* a powercycle is required to clear the TXT_RESET.STS flag */
    txt_ests_t ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
    return ests.txt_reset_sts;
}
