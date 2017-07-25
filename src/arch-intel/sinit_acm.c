#include "types.h"
#include "util.h"
#include "uuid.h"
#include "config.h"
#include "mle.h"
#include "acmod.h"
#include "mbi.h"
#include "misc.h"
#include "multiboot.h"

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

int prepare_sinit_acm(struct mbi *m) {
	out_description("Bhushan: prepare_sinit", m->mods_count);
	out_description("Bhushan: prepare_sinit tboot", ((multiboot_info_t *) m)->mods_count);
	for ( unsigned int i = (m->mods_count) - 1; i > 0; i-- ) {
		struct module *mod = get_module_mb1(m, i);
		out_string("Working on module :");
	//	out_string((const char *)mod->string);

		wait(4000);
		out_string("Working on module :\n");
		void *base2 = (void *)mod->mod_start;
		uint32_t size2 = mod->mod_end - (unsigned long)(base2);
		if (is_sinit_acmod(base2, size2)) {
			//1799              does_acmod_match_platform((acm_hdr_t *)base2) ) {
			out_string("SINIT matches platform\n");
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

