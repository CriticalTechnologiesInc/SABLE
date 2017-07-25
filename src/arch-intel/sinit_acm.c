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

__data acm_hdr_t *g_sinit = 0;


static acm_info_table_t *get_acmod_info_table(const acm_hdr_t* hdr)
{
 	uint32_t user_area_off;

	wait(4000);
 
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

	wait(4000);
	acm_hdr_t *acm_hdr = (acm_hdr_t *)acmod_base;

	/* first check size */
	if (acmod_size < sizeof(acm_hdr_t)) {
		out_string("ACM size is too small\n");
		out_description("acmod_size=",acmod_size);
		out_description("sizeof(acm_hdr)=", (uint32_t)sizeof(acm_hdr));
		return 0;
	}
 
	/* then check overflow */
	if (multiply_overflow_u32(acm_hdr->size, 4)) {
		out_string("ACM header size in bytes overflows\n");
		return 0;
	}

	/* then check size equivalency */
	if (acmod_size != acm_hdr->size * 4) {
		out_string("\t ACM size is too smal");
		out_description("acmod_size=", acmod_size);
		out_description("acm_hdr->size*4=", acm_hdr->size*4);
		return 0;
	}
 
	/* then check type and vendor */
	if ((acm_hdr->module_type != ACM_TYPE_CHIPSET) || (acm_hdr->module_vendor != ACM_VENDOR_INTEL)) {\
		out_string("\t ACM type/vendor mismatch");
		out_description("module_type=", acm_hdr->module_type);
		out_description("module_vendor=", acm_hdr->module_vendor);
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
	else if ( info_table->version > 5 ) {
		out_description("ACM info_table version mismatch", (uint32_t)info_table->version);
	}
	return 1;
}

int is_sinit_acmod(const void *acmod_base, uint32_t acmod_size)
{                   
	uint8_t type;

	wait(4000);
	if (!is_acmod(acmod_base, acmod_size, &type))
		return 0;

	if (type != ACM_CHIPSET_TYPE_SINIT) {
		out_description("ACM is not an SINIT ACM :", type);
		return 0;
	}         
	return 1;
} 
 
struct module *get_module_mb1(struct mbi *m, unsigned int i)
{
	
	wait(4000);
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
	out_description("chipset production fused", ver.prod_fused );
	out_info("chipset ids:");
	out_description("vendor", didvid.vendor_id); 
	out_description("device", didvid.device_id);
	out_description("revision", didvid.revision_id);

	/* get processor family/model/stepping and platform ID */

	uint64_t platform_id;
	uint32_t fms = cpuid_eax(1);
	platform_id = rdmsr(MSR_IA32_PLATFORM_ID);
	out_description("processor family/model/stepping", fms);
	out_description("platform id", (unsigned long long)platform_id);

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
	if ( chipset_id_list == NULL )
		return 0;

	out_description("ACM chipset id entries", chipset_id_list->count);
	unsigned int i;
	for ( i = 0; i < chipset_id_list->count; i++ ) {
		acm_chipset_id_t *chipset_id = &(chipset_id_list->chipset_ids[i]);
		
		out_description("vendor", (uint32_t)chipset_id->vendor_id);
		out_description("device", (uint32_t)chipset_id->device_id);
		out_description("flags", chipset_id->flags);
		out_description("revision", (uint32_t)chipset_id->revision_id);
		out_description("extended", chipset_id->extended_id);

		if ((didvid.vendor_id == chipset_id->vendor_id ) && 
		    (didvid.device_id == chipset_id->device_id ) &&
		    (didvid.device_id == chipset_id->device_id ) &&
		    ((((chipset_id->flags & 0x1) == 0) && (didvid.revision_id == chipset_id->revision_id)) ||
 		     (((chipset_id->flags & 0x1) == 1) && ((didvid.revision_id & chipset_id->revision_id) != 0)))) {
			break;
		}
		wait(3000);
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
		return 0;
	}

	if (info_table->version >= 4) {
		acm_processor_id_list_t *proc_id_list = get_acmod_processor_list(hdr);
		if (proc_id_list == NULL)
			return 0;

		out_description("ACM processor id entries count", proc_id_list->count);
		for ( i = 0; i < proc_id_list->count; i++ ) {
			acm_processor_id_t *proc_id = &(proc_id_list->processor_ids[i]);

			out_description("fms", proc_id->fms);
			out_description("fms_mask", proc_id->fms_mask);
			out_description("platform_id", (unsigned long long)proc_id->platform_id);
			out_description("platform_mask", (unsigned long long)proc_id->platform_mask);

			if ((proc_id->fms == (fms & proc_id->fms_mask)) && (proc_id->platform_id == (platform_id & proc_id->platform_mask))) {
				break;
			}
			wait(3000);
		}
		if ( i >= proc_id_list->count ) {
			out_info("ERROR : processor mismatch");
			return 0;
		}
	}
	return 1;
}

int prepare_sinit_acm(struct mbi *m) {
	out_description("Bhushan: prepare_sinit", m->mods_count);
	out_description("Bhushan: prepare_sinit tboot", ((multiboot_info_t *) m)->mods_count);
	for ( unsigned int i = (m->mods_count) - 1; i > 0; i-- ) {
		struct module *mod = get_module_mb1(m, i);
	//	out_string((const char *)mod->string);

		wait(4000);
		out_string("Working on module :\n");
		void *base2 = (void *)mod->mod_start;
		uint32_t size2 = mod->mod_end - (unsigned long)(base2);
		if (is_sinit_acmod(base2, size2)) {
			if (does_acmod_match_platform((acm_hdr_t *)base2)) { 
				out_string("SINIT matches platform\n");
				break;
			}
		} 
	}

	return 1;
}

#define MB_MAGIC			0x2badb002
#define MB2_HEADER_MAGIC		0xe85250d6
#define MB2_LOADER_MAGIC		0x36d76289

void determine_loader_type(uint32_t magic)
{
	switch (magic){
		case MB_MAGIC:
			out_info("MB1_ONLY");
			break;
		case MB2_LOADER_MAGIC: 
			out_info("MB2_ONLY : WE DONT SUPPORT");
			break;
		default:
			out_info("PROBLEM : no multi boot launch");
			break;
	}
}

