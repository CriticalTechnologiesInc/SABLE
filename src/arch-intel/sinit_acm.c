#include "types.h"
#include "util.h"
#include "uuid.h"
#include "config.h"
#include "mle.h"
#include "acmod.h"
#include "mbi.h"
#include "misc.h"
#include "multiboot.h"
#include "config_regs.h"
#include "processor.h"
#include "msr.h"
#include "mtrrs.h"
#include "hash.h"
#include "arch-intel/heap.h"
#include "smx.h"
#include "loader.h"

__data acm_hdr_t *g_sinit = 0;

#define CMDLINE_SIZE    512
 __text char g_cmdline[CMDLINE_SIZE] = { 0 };


/*
 * Bhushan: I am adding loader_ctx and it varible g_ldr_ctx just to make coding simple.
 * we dont need this structure and we can safely remove it by resolving all references. 
 */

/*
 * Code to be removed : start
 */

 /* loader context struct saved so that post_launch() can use it */
__data loader_ctx g_loader_ctx = { NULL, 0 };
__data loader_ctx *g_ldr_ctx = &g_loader_ctx;

/*
 * Code to be removed : end
 */


void print_txt_caps(txt_caps_t caps)
{
	#ifndef NDEBUG
	out_description("\tcapabilities: ", caps._raw);
	out_description("\trlp_wake_getsec: ", caps.rlp_wake_getsec);
	out_description("\trlp_wake_monitor: ", caps.rlp_wake_monitor);
	out_description("\tecx_pgtbl: ", caps.ecx_pgtbl);
	out_description("\tstm: ", caps.stm);
	out_description("\tpcr_map_no_legacy: ", caps.pcr_map_no_legacy);
	out_description("\tpcr_map_da: ", caps.pcr_map_da);
	out_description("\tplatform_type: ", caps.platform_type);
	out_description("\tmax_phy_addr: ", caps.max_phy_addr);
	out_description("\ttcg_event_log_format: ", caps.tcg_event_log_format);
	#endif
}

static acm_info_table_t *get_acmod_info_table(const acm_hdr_t* hdr)
{
 	uint32_t user_area_off;

	/* overflow? */
 	if (plus_overflow_u32(hdr->header_len, hdr->scratch_size)) {
 		out_string("ACM header length plus scratch size overflows\n");
		return NULL;
 	}

	if (multiply_overflow_u32((hdr->header_len + hdr->scratch_size), 4)) {
		out_string("ACM header length and scratch size in bytes overflows\n");
 		return NULL;
 	}

	/* this fn assumes that the ACM has already passed at least the initial */
	/* is_acmod() checks */
  
 	user_area_off = (hdr->header_len + hdr->scratch_size) * 4;
  
 	/* overflow? */
 	if (plus_overflow_u32(user_area_off, sizeof(acm_info_table_t))) {
		out_string("user_area_off plus acm_info_table_t size overflows\n");
		return NULL;
	}

	/* check that table is within module */
	if (user_area_off + sizeof(acm_info_table_t) > hdr->size*4) {
 		out_description("ACM info table size too large:", user_area_off + (uint32_t)sizeof(acm_info_table_t));
		return NULL;
 	}

	/* overflow? */
 	if (plus_overflow_u32((uint32_t)(uintptr_t)hdr, user_area_off)) {
 		out_string("hdr plus user_area_off overflows\n");
 		return NULL;
	}

	return (acm_info_table_t *)((unsigned long)hdr + user_area_off);
}


int is_acmod(const void *acmod_base, uint32_t acmod_size, uint8_t *type)
{
	acm_hdr_t *acm_hdr = (acm_hdr_t *)acmod_base;

	/* first check size */
	if (acmod_size < sizeof(acm_hdr_t)) {
		#ifndef NDEBUG
		out_string("ACM size is too small\n");
		out_description("acmod_size=",acmod_size);
		out_description("sizeof(acm_hdr)=", (uint32_t)sizeof(acm_hdr));
		#endif
		return 0;
	}
 
	/* then check overflow */
	if (multiply_overflow_u32(acm_hdr->size, 4)) {
		#ifndef NDEBUG
		out_string("ACM header size in bytes overflows\n");
		#endif
		return 0;
	}

	/* then check size equivalency */
	if (acmod_size != acm_hdr->size * 4) {
		#ifndef NDEBUG
		out_string("\t ACM size is too smal");
		out_description("acmod_size=", acmod_size);
		out_description("acm_hdr->size*4=", acm_hdr->size*4);
		#endif
		return 0;
	}
 
	/* then check type and vendor */
	if ((acm_hdr->module_type != ACM_TYPE_CHIPSET) || (acm_hdr->module_vendor != ACM_VENDOR_INTEL)) {
		#ifndef NDEBUG
		out_string("\t ACM type/vendor mismatch");
		out_description("module_type=", acm_hdr->module_type);
		out_description("module_vendor=", acm_hdr->module_vendor);
		#endif
		return 0;
	}

	acm_info_table_t *info_table = get_acmod_info_table(acm_hdr);
	if (info_table == NULL)
		return 0;

	/* check if ACM UUID is present */
	if (!are_uuids_equal(&(info_table->uuid), &((uuid_t)ACM_UUID_V3))) {
		out_info("unknown UUID: ");
		//print_uuid(&info_table->uuid);
		return 0;
	}

	if (type != NULL)
		*type = info_table->chipset_acm_type;

	if (info_table->version < 3) {
		out_description("info_table version unsupported", (uint32_t)info_table->version);
		return 0;
	}

	/* there is forward compatibility, so this is just a warning */
	else if (info_table->version > 5) {
		out_description("ACM info_table version mismatch", (uint32_t)info_table->version);
	}
	return 1;
}

int is_sinit_acmod(const void *acmod_base, uint32_t acmod_size){
	uint8_t type;

	if (!is_acmod(acmod_base, acmod_size, &type))
		return 0;

	if (type != ACM_CHIPSET_TYPE_SINIT) {
		out_description("ACM is not an SINIT ACM :", type);
		return 0;
	}
	return 1;
}

struct module *get_module_mb1(struct mbi *m, unsigned int i){
	if (m == NULL) {
		out_string("Error: mbi pointer is zero.\n");
		return NULL;
	}
	if (i >= m->mods_count) {
		out_string("invalid module #\n");
		return NULL;
	}
	return (struct module *)(m->mods_addr + i * sizeof(struct module));
}


static acm_chipset_id_list_t *get_acmod_chipset_list(const acm_hdr_t* hdr)
{   
	acm_info_table_t* info_table;
	uint32_t size, id_list_off;
	acm_chipset_id_list_t *chipset_id_list;

	/* this fn assumes that the ACM has already passed the is_acmod() checks */

	info_table = get_acmod_info_table(hdr);
	if ( info_table == NULL )
		return NULL;
	id_list_off = info_table->chipset_id_list;
    
	size = hdr->size * 4;
     
	/* overflow? */	
	if (plus_overflow_u32(id_list_off, sizeof(acm_chipset_id_t))) {
		out_info("id_list_off plus acm_chipset_id_t size overflows\n");
		return NULL;
	}

	/* check that chipset id table is w/in ACM */ 
	if (id_list_off + sizeof(acm_chipset_id_t) > size) {
		out_description("ACM chipset id list is too big: chipset_id_list", id_list_off);
		return NULL;
	}

	/* overflow? */
	if (plus_overflow_u32((uint32_t)(uintptr_t)hdr, id_list_off)) {
		out_info("hdr plus id_list_off overflows");
		return NULL;
	}

	chipset_id_list = (acm_chipset_id_list_t *) ((unsigned long)hdr + id_list_off);

	/* overflow? */

	if (multiply_overflow_u32(chipset_id_list->count, sizeof(acm_chipset_id_t))) {
		out_info("size of acm_chipset_id_list overflows");
		return NULL;
	}
	if (plus_overflow_u32(id_list_off + sizeof(acm_chipset_id_t), chipset_id_list->count * sizeof(acm_chipset_id_t))) {
		out_info("size of all entries overflows");
		return NULL;
	}

	/* check that all entries are w/in ACM */
	if (id_list_off + sizeof(acm_chipset_id_t) + chipset_id_list->count * sizeof(acm_chipset_id_t) > size ) {
		out_description("ACM chipset id entries are too big: chipset_id_list->count", chipset_id_list->count);
		return NULL;
	}

	return chipset_id_list;
}

static acm_processor_id_list_t *get_acmod_processor_list(const acm_hdr_t* hdr)
{
	acm_info_table_t* info_table;
	uint32_t size, id_list_off;
	acm_processor_id_list_t *proc_id_list;

	/* this fn assumes that the ACM has already passed the is_acmod() checks */
 
	info_table = get_acmod_info_table(hdr);
	if (info_table == NULL)
		return NULL;
	id_list_off = info_table->processor_id_list;

	size = hdr->size * 4;

	/* overflow? */
	if (plus_overflow_u32(id_list_off, sizeof(acm_processor_id_t))) {
		out_info("id_list_off plus acm_processor_id_t size overflows");
		return NULL;
	}

	/* check that processor id table is w/in ACM */
	if (id_list_off + sizeof(acm_processor_id_t) > size) {
		out_description("ACM processor id list is too big: processor_id_list", id_list_off);
		return NULL;
	}

	/* overflow? */
	if (plus_overflow_u32((unsigned long)hdr, id_list_off)) {
		out_info("hdr plus id_list_off overflows");
		return NULL;
	}

	proc_id_list = (acm_processor_id_list_t *) ((unsigned long)hdr + id_list_off);

	/* overflow? */
	if (multiply_overflow_u32(proc_id_list->count, sizeof(acm_processor_id_t))) {
		out_info("size of acm_processor_id_list overflows");
		return NULL;
	}
	if (plus_overflow_u32(id_list_off + sizeof(acm_processor_id_t), proc_id_list->count * sizeof(acm_processor_id_t))) {
		out_info("size of all entries overflows"); 
		return NULL;
	}

	/* check that all entries are w/in ACM */
	if (id_list_off + sizeof(acm_processor_id_t) + proc_id_list->count * sizeof(acm_processor_id_t) > size) {
		out_description("ACM processor id entries are too big: proc_id_list->count", proc_id_list->count);
		return NULL;
	}

	return proc_id_list;
}

int does_acmod_match_platform(const acm_hdr_t* hdr)
{
	/* this fn assumes that the ACM has already passed the is_sinit_acmod() checks */

	/* get chipset fusing, device, and vendor id info */

	txt_didvid_t didvid;
	didvid._raw = read_pub_config_reg(TXTCR_DIDVID);
	txt_ver_fsbif_qpiif_t ver;
	ver._raw = read_pub_config_reg(TXTCR_VER_FSBIF);
	if ((ver._raw & 0xffffffff) == 0xffffffff || (ver._raw & 0xffffffff) == 0x00) {         /* need to use VER.QPIIF */
		ver._raw = read_pub_config_reg(TXTCR_VER_QPIIF);
	}
	#ifndef NDEBUG
	out_description("chipset production fused", ver.prod_fused );
	out_info("chipset ids:");
	out_description("vendor", didvid.vendor_id); 
	out_description("device", didvid.device_id);
	out_description("revision", didvid.revision_id);
	#endif

	/* get processor family/model/stepping and platform ID */

	uint64_t platform_id;
	uint32_t fms = cpuid_eax(1);
	platform_id = rdmsr(MSR_IA32_PLATFORM_ID);
	#ifndef NDEBUG
	out_description("processor family/model/stepping", fms);
	out_description("platform id", (unsigned long long)platform_id);
	#endif

	/*
	 * check if chipset fusing is same
	 */

	if (ver.prod_fused != !hdr->flags.debug_signed ) {
		out_info("production/debug mismatch between chipset and ACM");
		return 0;
	}

	/*
	 * check if chipset vendor/device/revision IDs match
	 */

	acm_chipset_id_list_t *chipset_id_list = get_acmod_chipset_list(hdr);
	if (chipset_id_list == NULL) {
		out_info("Chipset ID is NULL");
		return 0;
	}

	#ifndef NDEBUG
	out_description("ACM chipset id entries", chipset_id_list->count);
	#endif

	unsigned int i;
	for ( i = 0; i < chipset_id_list->count; i++ ) {
		acm_chipset_id_t *chipset_id = &(chipset_id_list->chipset_ids[i]);

		#ifndef NDEBUG
		out_description("vendor", (uint32_t)chipset_id->vendor_id);
		out_description("device", (uint32_t)chipset_id->device_id);
		out_description("flags", chipset_id->flags);
		out_description("revision", (uint32_t)chipset_id->revision_id);
		out_description("extended", chipset_id->extended_id);
		#endif

		if ((didvid.vendor_id == chipset_id->vendor_id ) && 
		    (didvid.device_id == chipset_id->device_id ) &&
		    (didvid.device_id == chipset_id->device_id ) &&
		    ((((chipset_id->flags & 0x1) == 0) && (didvid.revision_id == chipset_id->revision_id)) ||
 		     (((chipset_id->flags & 0x1) == 1) && ((didvid.revision_id & chipset_id->revision_id) != 0)))) {
			break;
		}
	}
	if ( i >= chipset_id_list->count ) {
		out_info("ERROR: chipset id mismatch");
		return 0;
	}

	/*
	 * check if processor family/model/stepping and platform IDs match
	 */

	acm_info_table_t *info_table = get_acmod_info_table(hdr);
	if (info_table == NULL) {
		out_info("info_table is NULL");
		return 0;
	}

	if (info_table->version >= 4) {
		acm_processor_id_list_t *proc_id_list = get_acmod_processor_list(hdr);
		if (proc_id_list == NULL)
			return 0;

		#ifndef NDEBUG
		out_description("ACM processor id entries count", proc_id_list->count);
		#endif

		for ( i = 0; i < proc_id_list->count; i++ ) {
			acm_processor_id_t *proc_id = &(proc_id_list->processor_ids[i]);

			#ifndef NDEBUG
			out_description("fms", proc_id->fms);
			out_description("fms_mask", proc_id->fms_mask);
			out_description("platform_id", (unsigned long long)proc_id->platform_id);
			out_description("platform_mask", (unsigned long long)proc_id->platform_mask);
			#endif

			if ((proc_id->fms == (fms & proc_id->fms_mask)) && (proc_id->platform_id == (platform_id & proc_id->platform_mask))) {
				break;
			}
		}
		if ( i >= proc_id_list->count ) {
			out_info("ERROR : processor mismatch");
			return 0;
		}
	}
	return 1;
}

acm_hdr_t *get_bios_sinit(const void *sinit_region_base)
{
	if (sinit_region_base == NULL)
		return NULL;
	txt_heap_t *txt_heap = get_txt_heap();
	bios_data_t *bios_data = get_bios_data_start(txt_heap);

	if ( bios_data->bios_sinit_size == 0 )
		return NULL;

	/* BIOS has loaded an SINIT module, so verify that it is valid */
	out_info("BIOS has already loaded an SINIT module");

	/* is it a valid SINIT module? */
	if (!is_sinit_acmod(sinit_region_base, bios_data->bios_sinit_size) || !does_acmod_match_platform((acm_hdr_t *)sinit_region_base))
		return NULL;

	return (acm_hdr_t *)sinit_region_base;
}

acm_hdr_t *copy_sinit(const acm_hdr_t *sinit)
{   
	
	/* check if it is newer than BIOS provided version, then copy it to BIOS reserved region */
	/* get BIOS-reserved region from TXT.SINIT.BASE config reg */

	void *sinit_region_base = (void*)(unsigned long)read_pub_config_reg(TXTCR_SINIT_BASE);
	uint32_t sinit_region_size = (uint32_t)read_pub_config_reg(TXTCR_SINIT_SIZE);

	#ifndef NDEBUG
	out_description("TXT.SINIT.BASE", (unsigned int) sinit_region_base);
	out_description("TXT.SINIT.SIZE", (unsigned int) sinit_region_size);
	#endif

	/*
	 * check if BIOS already loaded an SINIT module there
	*/

	acm_hdr_t *bios_sinit = get_bios_sinit(sinit_region_base);
	if (bios_sinit != NULL) {
		/* no other SINIT was provided so must use one BIOS provided */
		if (sinit == NULL) {
			out_info("no SINIT provided by bootloader; using BIOS SINIT");
			return bios_sinit;
		}

		/* is it newer than the one we've been provided? */
		if (bios_sinit->date >= sinit->date) {
			out_info("BIOS-provided SINIT is newer, so using it");
			return bios_sinit;    /* yes */
		}
		else
			out_description("BIOS-provided SINIT is older: date", bios_sinit->date);
	}

	/* our SINIT is newer than BIOS's (or BIOS did not have one) */

	/* BIOS SINIT not present or not valid and none provided */
	if (sinit == NULL) {
		return NULL;
	}

	/* overflow? */
	if ( multiply_overflow_u32(sinit->size, 4) ) {
		out_info("sinit size in bytes overflows\n");
		return NULL;
	}
 
	/* make sure our SINIT fits in the reserved region */
	if ((sinit->size * 4) > sinit_region_size) {
		out_info("BIOS-reserved SINIT size is too small for loaded SINIT module");
		return NULL;
	}

	if (sinit_region_base == NULL) {
		return NULL;
	}

	/* copy it there */
	memcpy(sinit_region_base, sinit, sinit->size * 4);

	#ifndef NDEBUG
	out_info("\tcopied SINIT :");
	out_description("size", sinit->size*4);
	out_description("to base", (unsigned int)sinit_region_base);
	#endif

	return (acm_hdr_t *)sinit_region_base;
}


int verify_acmod(const acm_hdr_t *acm_hdr)
{
	getsec_parameters_t params;
	uint32_t size;

	/* assumes this already passed is_acmod() test */

	size = acm_hdr->size * 4;        /* hdr size is in dwords, we want bytes */
	/*
	* AC mod must start on 4k page boundary
	*/

	if ((unsigned long)acm_hdr & 0xfff) {
		out_description("AC mod base not 4K aligned", (unsigned int) acm_hdr);
		return 0;
	}
	#ifndef NDEBUG
	out_info("AC mod base alignment OK");
	#endif

	/* AC mod size must:
	 * - be multiple of 64
	 * - greater than ???
	 * - less than max supported size for this processor
	*/
	if ((size == 0) || ((size % 64) != 0)) {
		out_description("AC MOD size is not multiple of 64", size);
		return 0;
	}

	if (!get_parameters(&params)) {
		out_info("get_parameters() failed");
		return 0;
	}

	if (size > params.acm_max_size) {
		out_description("AC mod size too large:", size);
		out_description("max size", params.acm_max_size);
		return 0;
	}

	#ifndef NDEBUG
	out_info("AC mod size OK");
	#endif

	/*
	 * perform checks on AC mod structure
	 */

	/* entry point is offset from base addr so make sure it is within module */
	if (acm_hdr->entry_point >= size ) {
		out_description("AC mod entry ", acm_hdr->entry_point);
		out_description(" >= AC mod size", size);
		return 0;
	}

	/* overflow? */
	if (plus_overflow_u32(acm_hdr->seg_sel, 8)) {
		out_info("seg_sel plus 8 overflows");
		return 0;
	}

	if (!acm_hdr->seg_sel           ||       /* invalid selector */
	    (acm_hdr->seg_sel & 0x07)   ||       /* LDT, PL!=0 */
	    (acm_hdr->seg_sel + 8 > acm_hdr->gdt_limit) ) {
		out_description("AC mod selectorbogus", acm_hdr->seg_sel);
		return 0;
	}

	/*
	 * check for compatibility with this MLE
	 */

	acm_info_table_t *info_table = get_acmod_info_table(acm_hdr);
	if (info_table == NULL) {
		out_info("info table NULL");
		return 0;
	}

	/* check MLE header versions */

	/* I guess this check is tboot specific and we can remove it once we will have getsec[SENTER] code running */
	if (info_table->min_mle_hdr_ver > MLE_HDR_VER) {
		out_description("AC mod requires a newer MLE", info_table->min_mle_hdr_ver);
		return 0;
	}

	/* check capabilities */
	/* we need to match one of rlp_wake_{getsec, monitor} */
	txt_caps_t caps_mask = { 0 };
	caps_mask.rlp_wake_getsec = caps_mask.rlp_wake_monitor = 1;

	if (((MLE_HDR_CAPS & caps_mask._raw) & (info_table->capabilities._raw & caps_mask._raw)) == 0) {
		out_info("SINIT and MLE not support compatible RLP wake mechanisms");
		return 0;
	}
	/* we also expect ecx_pgtbl to be set */
	if (!info_table->capabilities.ecx_pgtbl) {
		out_info("SINIT does not support launch with MLE pagetable in ECX");
		/* TODO when SINIT ready
		 * return false;
		 */
	}

	/* check for version of OS to SINIT data */
	/* we don't support old versions */

	if ( info_table->os_sinit_data_ver < MIN_OS_SINIT_DATA_VER ) {
		out_description("SINIT's os_sinit_data version unsupported", info_table->os_sinit_data_ver);
		return 0;
	}
	/* only warn if SINIT supports more recent version than us */
	else if ( info_table->os_sinit_data_ver > MAX_OS_SINIT_DATA_VER ) {
		out_description("WORNING: SINIT's os_sinit_data version unsupported", info_table->os_sinit_data_ver);
	}

	return 1;
}


int prepare_sinit_acm(struct mbi *m) {
	void *base2=NULL;

	if (g_sinit != NULL) {

		/*
		 * Just temporary workaround
		 * Bhushan : in post launch we dont need to check for SINIT ACM module
		 * we expect g_sinit to be initialized already in pre_launch and skip 
		 * current search. ATTENTION we are assuming this is expected and retuning true.
		 * this might hide potential bugs. Have a closer look.
		 */

		out_info("ATTENTION : g_sinit is already intialized ..skipping SINIT operation");	
		return 1;
	}

	/*
	 * Step 1 : find SINIT ACM and match with platform in module list
	 */

	for ( unsigned int i = (m->mods_count) - 1; i > 0; i-- ) {
		struct module *mod = get_module_mb1(m, i);
		base2 = (void *)mod->mod_start;
		uint32_t size2 = mod->mod_end - (unsigned long)(base2);
		if (is_sinit_acmod(base2, size2)) {
			if (does_acmod_match_platform((acm_hdr_t *)base2)) { 
				#ifndef NDEBUG
				out_string("SINIT matches platform\n");
				#endif
				break;
			}
		} 
	}

	/*
	 * Step 2 : check BIOS already has newer SINIT ACM
	 */

	g_sinit = copy_sinit(base2);

	if (g_sinit == NULL) {
		out_info("ERROR : No SINIT ACM found");
		return 0;
	} 

	/*
	 * Step 3 : check SINIT is according to the requirements of SENTER
	 */

	if (!verify_acmod(g_sinit)) {
		return 0;
	}

	#ifndef NDEBUG
	out_info("Verification of SINIT ACM : done");
	#endif
	return 1;
}


void determine_loader_type_context(void *addr, uint32_t magic)
{
	/* TODO :  We can remove context initialization code (and all dependant code) if we will pass mbi from pre_launch to post_launch via stack */
	if (g_ldr_ctx->addr == NULL){
		/* brave new world */
		g_ldr_ctx->addr = addr;  /* save for post launch */
		g_ldr_ctx->type = MB1_ONLY;
		/* TODO: remove this flag initialization and test if its required one */
		multiboot_info_t *mbi = (multiboot_info_t *) addr;
		if (mbi->flags & MBI_AOUT) {
			mbi->flags &= ~MBI_AOUT;
		}
		if (mbi->flags & MBI_ELF){
			mbi->flags &= ~MBI_ELF;
		}
	}
	/* so at this point, g_ldr_ctx->type has one of three values:
	 * 0: not a multiboot launch--we're doomed
	 * 1: MB1 launch
	 * 2: MB2 launch
	 */
}

uint32_t get_supported_os_sinit_data_ver(const acm_hdr_t* hdr)
{
	/* assumes that it passed is_sinit_acmod() */

	acm_info_table_t *info_table = get_acmod_info_table(hdr);
	if (info_table == NULL) {
		return 0;
	}

	return info_table->os_sinit_data_ver;
}

txt_caps_t get_sinit_capabilities(const acm_hdr_t* hdr)
{
	/* assumes that it passed is_sinit_acmod() */

	acm_info_table_t *info_table = get_acmod_info_table(hdr);
	if ( info_table == NULL || info_table->version < 3 )
		return (txt_caps_t){ 0 };

	return info_table->capabilities;
}
