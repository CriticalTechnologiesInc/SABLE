/*
 * heap.c: fns for verifying and printing the Intel(r) TXT heap data structs
 *
 * Copyright (c) 2003-2011, Intel Corporation
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

#include "config.h"
#include "types.h"
#include "platform.h"
#include <misc.h>
#include "hash.h"
#include "util.h"
#include "config_regs.h"
#include "uuid.h"
#include "mle.h"
#include "acmod.h"
#include "mtrrs.h"
#include "arch-intel/heap.h"
#include "keyboard.h"

/*
 * extended data elements
 */

/* HEAP_BIOS_SPEC_VER_ELEMENT */
static void print_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
	const heap_bios_spec_ver_elt_t *bios_spec_ver_elt = (const heap_bios_spec_ver_elt_t *)elt->data;

	out_info("BIOS_SPEC_VER");
	out_description("major", bios_spec_ver_elt->spec_ver_major);
	out_description("minor", bios_spec_ver_elt->spec_ver_minor);
	out_description("trev", bios_spec_ver_elt->spec_ver_rev);
}

static int verify_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
	const heap_bios_spec_ver_elt_t *bios_spec_ver_elt = (const heap_bios_spec_ver_elt_t *)elt->data;

	if (elt->size != sizeof(*elt) + sizeof(*bios_spec_ver_elt)) {
		out_description("HEAP_BIOS_SPEC_VER element has wrong size", elt->size);
		return 0;
	}

	/* any values are allowed */
	return 1;
}

/* HEAP_ACM_ELEMENT */
static void print_acm_elt(const heap_ext_data_element_t *elt)
{
	const heap_acm_elt_t *acm_elt = (const heap_acm_elt_t *)elt->data;

	out_info("ACM:");
	out_description("\t\tnum_acms", acm_elt->num_acms);
	for (unsigned int i = 0; i < acm_elt->num_acms; i++) {
		out_description("\t\t     acm_addrs", acm_elt->acm_addrs[i]);
	}
}

static int verify_acm_elt(const heap_ext_data_element_t *elt)
{
	const heap_acm_elt_t *acm_elt = (const heap_acm_elt_t *)elt->data;

	if (elt->size != sizeof(*elt) + sizeof(*acm_elt) + acm_elt->num_acms*sizeof(uint64_t) ) {
		out_description("HEAP_ACM element has wrong size :", elt->size);
		return 0;
	}

	/* no addrs is not error, but print warning */
	if (acm_elt->num_acms == 0)
		out_info("WARNING: HEAP_ACM element has no ACM addrs");

	for (unsigned int i = 0; i < acm_elt->num_acms; i++) {
		if (acm_elt->acm_addrs[i] == 0) {
			out_description("HEAP_ACM element ACM addr is NULL. index:", i);
			return 0;
		}

		if (acm_elt->acm_addrs[i] >= 0x100000000UL) {
			out_description("HEAP_ACM element ACM addr is >4GB (0x%jx)\n", acm_elt->acm_addrs[i]);
			out_description("ERROR in index", i);
			return 0;
		}

	/* not going to check if ACM addrs are valid ACMs */
	}

	return 1;
}

/* HEAP_CUSTOM_ELEMENT */
static void print_custom_elt(const heap_ext_data_element_t *elt)
{
	const heap_custom_elt_t *custom_elt = (const heap_custom_elt_t *)elt->data;

	out_info("CUSTOM:");
	out_description("\t\t    size", elt->size);
	out_info("uuid");
	print_uuid(&custom_elt->uuid);            
}

static int  verify_custom_elt(const heap_ext_data_element_t *elt)
{
	const heap_custom_elt_t *custom_elt = (const heap_custom_elt_t *)elt->data;

	if (elt->size < sizeof(*elt) + sizeof(*custom_elt)) {
		out_description("HEAP_CUSTOM element has wrong size :", elt->size);
		return 0;
	}

	/* any values are allowed */
	return 1;
}

/* HEAP_EVENT_LOG_POINTER_ELEMENT */
static inline void print_heap_hash(const sha1_hash_t hash)
{
	//print_hash((const tb_hash_t *)hash, TB_HALG_SHA1);
	hex_dump((unsigned char *)hash, SHA1_LENGTH);
}

void print_event(const tpm12_pcr_event_t *evt)
{
	out_info("\t\t\t Event:");
	out_description("\t\t\t     PCRIndex", evt->pcr_index);
	out_description("\t\t\t     Type", evt->type);
	out_info("\t\t\t     Digest: ");
	print_heap_hash(evt->digest);
	out_description("\t\t\t     Data: bytes", evt->data_size);
//	print_hex("\t\t\t         ", evt->data, evt->data_size);
}

static void print_evt_log(const event_log_container_t *elog)
{
	out_info("Event Log Container");
	wait(3000);
	/* Bhushan: This can cause screen to go black as signature might not contain null char at end */
	out_info("\t\t\t     Signature:");
	out_string((char *)elog->signature);
	out_info("\t\t\t   ContainerVer");
	out_description("\t\t\t   major", elog->container_ver_major);
	out_description("\t\t\t   minor", elog->container_ver_minor);
	out_info("\t\t\t   PCREventVer");
	out_description("\t\t\t   major", elog->pcr_event_ver_major);
	out_description("\t\t\t   minor", elog->pcr_event_ver_minor);
	out_description("\t\t\t          Size", elog->size);
	out_info("\t\t\t  EventsOffset:");
	out_description("pcr_events_offset", elog->pcr_events_offset);
	out_description("next_event_offset", elog->next_event_offset);

	const tpm12_pcr_event_t *curr, *next;
	curr = (tpm12_pcr_event_t *)((void*)elog + elog->pcr_events_offset);
	next = (tpm12_pcr_event_t *)((void*)elog + elog->next_event_offset);

	while (curr < next) {
		print_event(curr);
		curr = (void *)curr + sizeof(*curr) + curr->data_size;
	}
}

static int verify_evt_log(const event_log_container_t *elog)
{
	if ( elog == NULL ) {
		out_info("Event log container pointer is NULL\n");
		return 0;
	}

	if (memcmp(elog->signature, EVTLOG_SIGNATURE, sizeof(elog->signature)) ) {
		out_info("Bad event log container signature");
		/* Bhushan: This can cause screen to go black as signature might not contain null char at end */
		// wait(2000);
		// out_string(elog->signature);
		return 0;
	}

	if (elog->size != MAX_EVENT_LOG_SIZE) {
		out_description("Bad event log container size: 0x%x\n", elog->size);
		return 0;
	}

	/* no need to check versions */

	if (elog->pcr_events_offset < sizeof(*elog) ||
		elog->next_event_offset < elog->pcr_events_offset ||
		elog->next_event_offset > elog->size ) {
		out_info("Bad events offset range");
		out_description("elog->pcr_events_offset", elog->pcr_events_offset);
		out_description("elog->next_event_offset", elog->next_event_offset);
		return 0;
	}

	return 1;
}

static void print_evt_log_ptr_elt(const heap_ext_data_element_t *elt)
{
	const heap_event_log_ptr_elt_t *elog_elt = (const heap_event_log_ptr_elt_t *)elt->data;

	out_info("EVENT_LOG_POINTER");
	out_description("size ", elt->size);
	out_description64("elog_addr ", elog_elt->event_log_phys_addr);

	if (elog_elt->event_log_phys_addr) {
		print_evt_log((event_log_container_t *)(unsigned long) elog_elt->event_log_phys_addr);
	}
}

static bool verify_evt_log_ptr_elt(const heap_ext_data_element_t *elt)
{
	const heap_event_log_ptr_elt_t *elog_elt = (const heap_event_log_ptr_elt_t *)elt->data;

	if (elt->size != sizeof(*elt) + sizeof(*elog_elt)) {
		out_description("HEAP_EVENT_LOG_POINTER element has wrong size :", elt->size);
		return 0;
	}

	return verify_evt_log((event_log_container_t *)(unsigned long) elog_elt->event_log_phys_addr);
}

static void print_evt_log_ptr_elt_2(const heap_ext_data_element_t *elt)
{
	out_info("ERROR : printing not supported : heap_ext_data_element_t");
	wait(3000);
}


static void print_evt_log_ptr_elt_2_1(const heap_ext_data_element_t *elt)
{
	out_info("ERROR: Printing not supported : heap_ext_data_element_t");
	wait(3000);
}


static int verify_evt_log_ptr_elt_2(const heap_ext_data_element_t *elt)
{
	if ( !elt )
		return 0;
	return 1;
}

static void print_ext_data_elts(const heap_ext_data_element_t elts[])
{
	const heap_ext_data_element_t *elt = elts;

	out_info("ext_data_elts[]");
	while (elt->type != HEAP_EXTDATA_TYPE_END) {
		switch (elt->type) {
			case HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
				print_bios_spec_ver_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_ACM:
				print_acm_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_CUSTOM:
				print_custom_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
				print_evt_log_ptr_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2:
				print_evt_log_ptr_elt_2(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2_1:
				print_evt_log_ptr_elt_2_1(elt);
				break;
			default:
				out_info("unknown element");
				out_description("type:", elt->type);
				out_description("size:", elt->size);
				break;
		}
		elt = (void *)elt + elt->size;
	}
}

static bool verify_ext_data_elts(const heap_ext_data_element_t elts[], size_t elts_size)
{
	const heap_ext_data_element_t *elt = elts;

	while (1) {
		if (elts_size < sizeof(*elt)) {
			out_info("heap ext data elements too small");
			return 0;
		}
		if (elts_size < elt->size || elt->size == 0) {
			out_info("invalid element size");
			out_description("type:", elt->type);
			out_description("size:", elt->size);
			return 0;
		}
		switch ( elt->type ) {
			case HEAP_EXTDATA_TYPE_END:
				return 1;
			case HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
				if (!verify_bios_spec_ver_elt(elt))
					return 0;
				break;
			case HEAP_EXTDATA_TYPE_ACM:
				if (!verify_acm_elt(elt))
					return 0;
				break;
			case HEAP_EXTDATA_TYPE_CUSTOM:
				if (!verify_custom_elt(elt))
					return 0;
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
				if (!verify_evt_log_ptr_elt(elt))
					return 0;
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2:
				if (!verify_evt_log_ptr_elt_2(elt))
					return 0;
				break;
			default:
				out_info("unknown element");
				out_description("type:", elt->type);
				out_description("size:", elt->size);
				break;
		}
		elts_size -= elt->size;
		elt = (void *)elt + elt->size;
	}
	return 1;
}

int verify_bios_data(const txt_heap_t *txt_heap)
{
	uint64_t heap_base = read_pub_config_reg(TXTCR_HEAP_BASE);
	uint64_t heap_size = read_pub_config_reg(TXTCR_HEAP_SIZE);
	out_description("TXT.HEAP.BASE: ", heap_base);
	out_description("TXT.HEAP.SIZE: ", heap_size);

	/* verify that heap base/size are valid */
	if (txt_heap == NULL || heap_base == 0 || heap_size == 0) {
		out_info("HEAP : Invalide size");
		return 0;
	}

	/* check size */
	uint64_t size = get_bios_data_size(txt_heap);
	if ( size == 0 ) {
		out_info("BIOS data size is 0\n");
		return 0;
	}
	if (size > heap_size) {
		out_info("BIOS data size is larger than heap size");
		out_description("size", size);
		out_description("headp size", heap_size);
		return 0;
	}

	bios_data_t *bios_data = get_bios_data_start(txt_heap);

	/* check version */
	if (bios_data->version < 2) {
		out_description("unsupported BIOS data version", bios_data->version);
		return 0;
	}
	/* we assume backwards compatibility but print a warning */
	if (bios_data->version > 4) {
		out_description("Just Warning: unsupported BIOS data version:", bios_data->version);
	}

	/* all TXT-capable CPUs support at least 1 core */
	if (bios_data->num_logical_procs < 1 ) {
		out_description("BIOS data has incorrect num_logical_procs:", bios_data->num_logical_procs);
		return 0;
	}
	else if (bios_data->num_logical_procs > NR_CPUS) {
		out_description("BIOS data specifies too many CPUs:", bios_data->num_logical_procs);
		return 0;
	}

	if (bios_data->version >= 4 && size > sizeof(*bios_data) + sizeof(size)) {
		 if (!verify_ext_data_elts(bios_data->ext_data_elts, size - sizeof(*bios_data) - sizeof(size)))
			return 0;
	}

	// print_bios_data(bios_data, size);

	return 1;
}

static void print_os_mle_data(const os_mle_data_t *os_mle_data)
{
	out_info("os_mle_data");
	out_description("os_mle_data address", (unsigned int)os_mle_data);
	out_description("  o size", *((uint64_t *)os_mle_data - 1));
	out_description("  o version", os_mle_data->version);
	/* TBD: perhaps eventually print saved_mtrr_state field */
	out_description("      o loader context addr", (unsigned int)os_mle_data->lctx_addr);
}

static bool verify_os_mle_data(const txt_heap_t *txt_heap)
{
	uint64_t size, heap_size;
	os_mle_data_t *os_mle_data;

	/* check size */
	heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
	size = get_os_mle_data_size(txt_heap);
	if (size == 0) {
		out_info("OS to MLE data size is 0");
		return 0;
	}
	if (size > heap_size) {
		out_info("OS to MLE data size is larger than heap size");
		out_description("size", size);
		out_description("head size", heap_size);
		return 0;
	}
	if (size != (sizeof(os_mle_data_t) + sizeof(size))) {
		out_info("OS to MLE data size is not equal to os_mle_data_t + size");
		out_description("size", size);
		out_description("size of os_mle_data", sizeof(os_mle_data_t));
		return 0;
	}

	os_mle_data = get_os_mle_data_start(txt_heap);

	/* check version */
	/* since this data is from our pre-launch to post-launch code only, it */
	/* should always be this */
	if (os_mle_data->version != 3) {
		out_description("unsupported OS to MLE data version", os_mle_data->version);
		return 0;
	}

	/* field checks */
	if (os_mle_data->lctx_addr == NULL ) {
		out_info("REMOVE THIS CODE : OS to MLE data loader context addr field is NULL");
		wait(2000);
		// return 0;
	}

	print_os_mle_data(os_mle_data);

	return 1;
}

/*
 * Make sure version is in [MIN_OS_SINIT_DATA_VER, MAX_OS_SINIT_DATA_VER]
 * before calling calc_os_sinit_data_size
 */

uint64_t calc_os_sinit_data_size(uint32_t version)
{
	uint64_t size[] = {
		offsetof(os_sinit_data_t, efi_rsdt_ptr) + sizeof(uint64_t),
		sizeof(os_sinit_data_t) + sizeof(uint64_t),
		sizeof(os_sinit_data_t) + sizeof(uint64_t) +
		2 * sizeof(heap_ext_data_element_t) +
		sizeof(heap_event_log_ptr_elt_t)
	};

	if (version >= 6)
		return size[2];
	else
		return size[version - MIN_OS_SINIT_DATA_VER];
}

void print_os_sinit_data(const os_sinit_data_t *os_sinit_data)
{
	out_info("os_sinit_data");
	out_description("os_sinit_data", (unsigned int)os_sinit_data);
	out_description64("os_sinit_data - 1", *((uint64_t *)os_sinit_data - 1));
	out_description("version", os_sinit_data->version);
	out_description("flags", os_sinit_data->flags);
	out_description64("mle_ptab", os_sinit_data->mle_ptab);
	out_description64("mle_size", os_sinit_data->mle_size);
	out_description64("mle_hdr_base", os_sinit_data->mle_hdr_base);
	out_description64("vtd_pmr_lo_base", os_sinit_data->vtd_pmr_lo_base);
	out_description64("vtd_pmr_lo_size", os_sinit_data->vtd_pmr_lo_size);
	out_description64("vtd_pmr_hi_base", os_sinit_data->vtd_pmr_hi_base);
	out_description64("vtd_pmr_hi_size", os_sinit_data->vtd_pmr_hi_size);
	out_description64("lcp_po_base", os_sinit_data->lcp_po_base);
	out_description64("lcp_po_size", os_sinit_data->lcp_po_size);
	print_txt_caps(os_sinit_data->capabilities);
	if (os_sinit_data->version >= 5) {
		out_description64("efi_rsdt_ptr", os_sinit_data->efi_rsdt_ptr);
	}
	if (os_sinit_data->version >= 6) {
		print_ext_data_elts(os_sinit_data->ext_data_elts);
	}
}

static bool verify_os_sinit_data(const txt_heap_t *txt_heap)
{
	uint64_t size, heap_size;
	os_sinit_data_t *os_sinit_data;

	/* check size */
	heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
	size = get_os_sinit_data_size(txt_heap);
	if (size == 0) {
		out_info("OS to SINIT data size is 0\n");
		return 0;
	}
	if ( size > heap_size ) {
		out_info("OS to SINIT data size is larger than heap size");
		out_description("size", size);
		out_description("heap_size", heap_size);
		return 0;
	}

	os_sinit_data = get_os_sinit_data_start(txt_heap);

	/* check version (but since we create this, it should always be OK) */
	if (os_sinit_data->version < MIN_OS_SINIT_DATA_VER || os_sinit_data->version > MAX_OS_SINIT_DATA_VER ) {
		out_description("unsupported OS to SINIT data version", os_sinit_data->version);
		return 0;
	}

	if ( size != calc_os_sinit_data_size(os_sinit_data->version) ) {
		out_info("OS to SINIT data size (%Lx) does not match for version");
		out_description("size", size);
		out_description("os_sinit_data_t",  sizeof(os_sinit_data_t));
		return 0;
	}

	if (os_sinit_data->version >= 6) {
		if (!verify_ext_data_elts(os_sinit_data->ext_data_elts, size - sizeof(*os_sinit_data) - sizeof(size)) )
			return 0;
	}

	print_os_sinit_data(os_sinit_data);

	return 1;
}

//static void print_sinit_mdrs(const sinit_mdr_t mdrs[], uint32_t num_mdrs)
//{
//    static const char *mem_types[] = {"GOOD", "SMRAM OVERLAY",
//                                      "SMRAM NON-OVERLAY",
//                                      "PCIE EXTENDED CONFIG", "PROTECTED"};
//
//    printk(TBOOT_DETA"\t sinit_mdrs:\n");
//    for ( unsigned int i = 0; i < num_mdrs; i++ ) {
//        printk(TBOOT_DETA"\t\t %016Lx - %016Lx ", mdrs[i].base,
//               mdrs[i].base + mdrs[i].length);
//        if ( mdrs[i].mem_type < sizeof(mem_types)/sizeof(mem_types[0]) )
//            printk(TBOOT_DETA"(%s)\n", mem_types[mdrs[i].mem_type]);
//        else
//            printk(TBOOT_DETA"(%d)\n", (int)mdrs[i].mem_type);
//    }
//}

static void print_sinit_mle_data(const sinit_mle_data_t *sinit_mle_data)
{
	out_info("sinit_mle_data");
	out_description("    sinit_mle_data", (int unsigned)sinit_mle_data);
//           *((uint64_t *)sinit_mle_data - 1));
	out_description("    version:", sinit_mle_data->version);
	out_info("    bios_acm_id:");
	print_heap_hash(sinit_mle_data->bios_acm_id);
	out_description("    edx_senter_flags", sinit_mle_data->edx_senter_flags);
	out_description("    mseg_valid", sinit_mle_data->mseg_valid);
	out_info("sinit_hash:"); 
	print_heap_hash(sinit_mle_data->sinit_hash);
	out_info("mle_hash:"); 
	print_heap_hash(sinit_mle_data->mle_hash);
	out_info("stm_hash:"); 
	print_heap_hash(sinit_mle_data->stm_hash);
	out_info("lcp_policy_hash:");
		print_heap_hash(sinit_mle_data->lcp_policy_hash);
	out_description("lcp_policy_control ", sinit_mle_data->lcp_policy_control);
	out_description("rlp_wakeup_addr ", sinit_mle_data->rlp_wakeup_addr);
	out_description("num_mdrs ", sinit_mle_data->num_mdrs);
	out_description("mdrs_off ", sinit_mle_data->mdrs_off);
	out_description("num_vtd_dmars ", sinit_mle_data->num_vtd_dmars);
	out_description("vtd_dmars_off ", sinit_mle_data->vtd_dmars_off);
//    print_sinit_mdrs((sinit_mdr_t *)
//                     (((void *)sinit_mle_data - sizeof(uint64_t)) +
//                      sinit_mle_data->mdrs_off), sinit_mle_data->num_mdrs);
	if (sinit_mle_data->version >= 8)
		out_description("proc_scrtm_status ", sinit_mle_data->proc_scrtm_status);
	if (sinit_mle_data->version >= 9)
		print_ext_data_elts(sinit_mle_data->ext_data_elts);
	out_info("BHUSHAN : CHECK RPL WAKEUP ADD");
	WAIT_FOR_INPUT();
}

static bool verify_sinit_mle_data(const txt_heap_t *txt_heap)
{
	uint64_t size, heap_size;
	sinit_mle_data_t *sinit_mle_data;

	/* check size */
	heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
	size = get_sinit_mle_data_size(txt_heap);
	if ( size == 0 ) {
		out_info("SINIT to MLE data size is 0\n");
		return 0;
	}
	if ( size > heap_size ) {
		out_info("SINIT to MLE data size is larger than heap size");
		return 0;
	}

	sinit_mle_data = get_sinit_mle_data_start(txt_heap);

	/* check version */
	if ( sinit_mle_data->version < 6 ) {
		out_description("unsupported SINIT to MLE data version", sinit_mle_data->version);
		return 0;
	}
	else if ( sinit_mle_data->version > 9 ) {
		out_description("unsupported SINIT to MLE data version", sinit_mle_data->version);
	}

	/* this data is generated by SINIT and so is implicitly trustworthy, */
	/* so we don't need to validate it's fields */

	print_sinit_mle_data(sinit_mle_data);

	return 1;
}

int verify_txt_heap(const txt_heap_t *txt_heap, int bios_data_only)
{
	/* verify BIOS to OS data */
	if (!verify_bios_data(txt_heap)) {
		return 0;
	}

	if (bios_data_only) {
		return 1;
	}


	/* check that total size is within the heap */
	uint64_t size1 = get_bios_data_size(txt_heap);
	uint64_t size2 = get_os_mle_data_size(txt_heap);
	uint64_t size3 = get_os_sinit_data_size(txt_heap);
	uint64_t size4 = get_sinit_mle_data_size(txt_heap);

	/* overflow? */
	if (plus_overflow_u64(size1, size2)) {
		out_info("TXT heap data size overflows");
		return 0;
	}

	if (plus_overflow_u64(size3, size4)) {
		out_info("TXT heap data size overflows");
		return 0;
	}
	if ( plus_overflow_u64(size1 + size2, size3 + size4) ) {
		out_info("TXT heap data size overflows");
		return 0;
	}

	if ( (size1 + size2 + size3 + size4) >
		read_priv_config_reg(TXTCR_HEAP_SIZE) ) {
		out_info("TXT heap data sizes size1, size2, size3, size4, are larger than heap total");
		return 0;
	}

	/* verify OS to MLE data */
	if ( !verify_os_mle_data(txt_heap) )
		return 0;

	/* verify OS to SINIT data */
	if ( !verify_os_sinit_data(txt_heap) )
		return 0;

	/* verify SINIT to MLE data */
	if ( !verify_sinit_mle_data(txt_heap) )
		return 0;

	return 1;
}
