///*
// * heap.c: fns for verifying and printing the Intel(r) TXT heap data structs
// *
// * Copyright (c) 2003-2011, Intel Corporation
// * All rights reserved.
// *
// * Redistribution and use in source and binary forms, with or without
// * modification, are permitted provided that the following conditions
// * are met:
// *
// *   * Redistributions of source code must retain the above copyright
// *     notice, this list of conditions and the following disclaimer.
// *   * Redistributions in binary form must reproduce the above
// *     copyright notice, this list of conditions and the following
// *     disclaimer in the documentation and/or other materials provided
// *     with the distribution.
// *   * Neither the name of the Intel Corporation nor the names of its
// *     contributors may be used to endorse or promote products derived
// *     from this software without specific prior written permission.
// *
// * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// * OF THE POSSIBILITY OF SUCH DAMAGE.
// *
// */
//
//#ifndef IS_INCLUDED
#include "config.h"
#include "types.h"
#include "platform.h"
//#include <stdbool.h>
//#include <compiler.h>
//#include <string.h>
//#include <printk.h>
//#include <multiboot.h>
//#include <mle.h>
#include <misc.h>
#include "hash.h"
//#include <tpm.h>
//#include <txt/mtrrs.h>
#include "util.h"
#include "config_regs.h"
#include "uuid.h"
#include "mle.h"
#include "acmod.h"
#include "mtrrs.h"
#include "heap.h"
//#endif
//
///*
// * extended data elements
// */
//
///* HEAP_BIOS_SPEC_VER_ELEMENT */
static void print_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
	const heap_bios_spec_ver_elt_t *bios_spec_ver_elt = (const heap_bios_spec_ver_elt_t *)elt->data;

	out_info("\t\tBIOS_SPEC_VER");
	out_description("\t\tmajor", bios_spec_ver_elt->spec_ver_major);
	out_description("\t\tminor", bios_spec_ver_elt->spec_ver_minor);
	out_description("\t\trev", bios_spec_ver_elt->spec_ver_rev);
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

///* HEAP_EVENT_LOG_POINTER_ELEMENT */
//static inline void print_heap_hash(const sha1_hash_t hash)
//{
//    print_hash((const tb_hash_t *)hash, TB_HALG_SHA1);
//}

void print_event(const tpm12_pcr_event_t *evt)
{
	out_info("\t\t\t Event:");
	out_description("\t\t\t     PCRIndex", evt->pcr_index);
	out_description("\t\t\t     Type", evt->type);
	out_info("\t\t\t     Digest: ");
//	print_heap_hash(evt->digest);
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
	//	wait(2000);
	//	out_string(elog->signature);
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

//void print_event_2(void *evt, uint16_t alg)
//{
//    uint32_t hash_size, data_size; 
//    void *next = evt;
//
//    hash_size = get_hash_size(alg); 
//    if ( hash_size == 0 )
//        return;
//
//    printk(TBOOT_DETA"\t\t\t Event:\n");
//    printk(TBOOT_DETA"\t\t\t     PCRIndex: %u\n", *((uint32_t *)next));
//    
//    if ( *((uint32_t *)next) > 24 && *((uint32_t *)next) != 0xFF ) {
//         printk(TBOOT_DETA"\t\t\t           Wrong Event Log.\n");
//         return;
//     }
//    
//    next += sizeof(uint32_t);
//    printk(TBOOT_DETA"\t\t\t         Type: 0x%x\n", *((uint32_t *)next));
//
//    if ( *((uint32_t *)next) > 0xFFF ) {
//        printk(TBOOT_DETA"\t\t\t           Wrong Event Log.\n");
//        return;
//    }
//
//    next += sizeof(uint32_t);
//    printk(TBOOT_DETA"\t\t\t       Digest: ");
//    print_hex(NULL, (uint8_t *)next, hash_size);
//    next += hash_size;
//    data_size = *(uint32_t *)next;
//    printk(TBOOT_DETA"\t\t\t         Data: %u bytes", data_size);
//    if ( data_size > 4096 ) {
//        printk(TBOOT_DETA"\t\t\t           Wrong Event Log.\n");
//        return;
//    }
//
//    next += sizeof(uint32_t);
//    if ( data_size )
//         print_hex("\t\t\t         ", (uint8_t *)next, data_size);
//    else
//         printk(TBOOT_DETA"\n");
//}
//
//uint32_t print_event_2_1_log_header(void *evt){
//
//   tcg_pcr_event *evt_ptr = (tcg_pcr_event *)evt;
//   tcg_efi_specid_event_strcut *evt_data_ptr = (tcg_efi_specid_event_strcut *) evt_ptr->event_data;
//
//   printk(TBOOT_DETA"\t TCG Event Log Header:\n");
//   printk(TBOOT_DETA"\t\t       pcr_index: %u\n", evt_ptr->pcr_index);
//   printk(TBOOT_DETA"\t\t      event_type: %u\n", evt_ptr->event_type);
//   printk(TBOOT_DETA"\t\t          digest: %s\n", evt_ptr->digest);
//   printk(TBOOT_DETA"\t\t event_data_size: %u\n", evt_ptr->event_data_size);
//
//   // print out event log header data
//
//   printk(TBOOT_DETA"\t\t 	   header event data:  \n"); 
//   printk(TBOOT_DETA"\t\t\t              signature: %s\n", evt_data_ptr->signature);
//   printk(TBOOT_DETA"\t\t\t         platform_class: %u\n", evt_data_ptr->platform_class);
//   printk(TBOOT_DETA"\t\t\t     spec_version_major: %u\n", evt_data_ptr->spec_version_major);
//   printk(TBOOT_DETA"\t\t\t     spec_version_minor: %u\n", evt_data_ptr->spec_version_minor);
//   printk(TBOOT_DETA"\t\t\t            spec_errata: %u\n", evt_data_ptr->spec_errata);
//   printk(TBOOT_DETA"\t\t\t             uintn_size: %u\n", evt_data_ptr->uintn_size);
//   printk(TBOOT_DETA"\t\t\t   number_of_algorithms: %u\n", evt_data_ptr->number_of_algorithms);
//
//   for ( uint32_t i = 0; i < evt_data_ptr->number_of_algorithms; i++){
//       printk(TBOOT_DETA"\t\t\t\t   algorithm_id: 0x%x \n", evt_data_ptr->digestSizes[i].algorithm_id);
//       printk(TBOOT_DETA"\t\t\t\t    digest_size: %u\n", evt_data_ptr->digestSizes[i].digest_size);
//   }
//   
//   printk(TBOOT_DETA"\t\t\t       vendor_info: %u bytes\n", evt_data_ptr->vendor_info_size);
//   print_hex(NULL, evt_data_ptr->vendor_info, evt_data_ptr->vendor_info_size);
//
//   return evt_ptr->event_data_size;
//}
//uint32_t print_event_2_1(void *evt)
//{
//   
//    tcg_pcr_event2 *evt_ptr = (tcg_pcr_event2 *)evt;
//    uint8_t *evt_data_ptr;
//    uint16_t hash_alg;
//    uint32_t event_size = 0;
//    printk(TBOOT_DETA"\t\t\t TCG Event:\n");
//    printk(TBOOT_DETA"\t\t\t      pcr_index: %u\n", evt_ptr->pcr_index);
//    printk(TBOOT_DETA"\t\t\t     event_type: 0x%x\n", evt_ptr->event_type);
//    printk(TBOOT_DETA"\t\t\t          count: %u\n", evt_ptr->digest.count);
//    if (evt_ptr->digest.count != 0) {
//	evt_data_ptr = (uint8_t *)evt_ptr->digest.digests[0].digest;
//        hash_alg = evt_ptr->digest.digests[0].hash_alg;
//	for (uint32_t i = 0; i < evt_ptr->digest.count; i++ ) { 
//    	    switch (hash_alg) {
//                case TB_HALG_SHA1:
//				printk(TBOOT_INFO"SHA1: \n");
//				print_hex(NULL, evt_data_ptr, SHA1_LENGTH);
//				evt_data_ptr += SHA1_LENGTH;
//				break;
//
//                case TB_HALG_SHA256:
//				printk(TBOOT_INFO"SHA256: \n");
//				print_hex(NULL, evt_data_ptr, SHA256_LENGTH);
//					evt_data_ptr += SHA256_LENGTH;
//				break;
//
//                case TB_HALG_SM3:
//				printk(TBOOT_INFO"SM3_256: \n");
//				print_hex(NULL, evt_data_ptr, SM3_LENGTH);
//				evt_data_ptr += SM3_LENGTH;
//				break;
//
//                case TB_HALG_SHA384:
//				printk(TBOOT_INFO"SHA384: \n");
//				print_hex(NULL, evt_data_ptr, SHA384_LENGTH);
//				evt_data_ptr += SHA384_LENGTH;				
//				break;
//
//                case TB_HALG_SHA512:
//				printk(TBOOT_INFO"SHA512:  \n");
//				print_hex(NULL, evt_data_ptr, SHA512_LENGTH);
//				evt_data_ptr += SHA512_LENGTH;
//				break;
//                default:
//	                        printk(TBOOT_ERR"Unsupported algorithm: %u\n", evt_ptr->digest.digests[i].hash_alg);
//	 }
//         hash_alg = (uint16_t)*evt_data_ptr;
//	 evt_data_ptr += sizeof(uint16_t);
//      }
//      evt_data_ptr -= sizeof(uint16_t);
//      event_size = (uint32_t)*evt_data_ptr;
//      printk(TBOOT_DETA"\t\t\t     event_data: %u bytes", event_size);
//      evt_data_ptr += sizeof(uint32_t);
//      print_hex("\t\t\t     ", evt_data_ptr, event_size);
//    }
//    else { 
//        printk(TBOOT_DETA"sth wrong in TCG event log: algoritm count = %u\n", evt_ptr->digest.count);
//        evt_data_ptr= (uint8_t *)evt +12;
//    }
//    return (evt_data_ptr + event_size - (uint8_t *)evt);
//}
//
static void print_evt_log_ptr_elt_2(const heap_ext_data_element_t *elt)
{
	out_info("ERROR : printing not supported : heap_ext_data_element_t");
	wait(3000);
//    const heap_event_log_ptr_elt2_t *elog_elt =
//              (const heap_event_log_ptr_elt2_t *)elt->data;
//    const heap_event_log_descr_t *log_descr;
//
//    printk(TBOOT_DETA"\t\t EVENT_LOG_PTR:\n");
//    printk(TBOOT_DETA"\t\t       size: %u\n", elt->size);
//    printk(TBOOT_DETA"\t\t      count: %d\n", elog_elt->count);
//
//    for ( unsigned int i=0; i<elog_elt->count; i++ ) {
//        log_descr = &elog_elt->event_log_descr[i];
//        printk(TBOOT_DETA"\t\t\t Log Descrption:\n");
//        printk(TBOOT_DETA"\t\t\t             Alg: %u\n", log_descr->alg);
//        printk(TBOOT_DETA"\t\t\t            Size: %u\n", log_descr->size);
//        printk(TBOOT_DETA"\t\t\t    EventsOffset: [%u,%u]\n",
//                log_descr->pcr_events_offset,
//                log_descr->next_event_offset);
//
//        if (log_descr->pcr_events_offset == log_descr->next_event_offset) {
//            printk(TBOOT_DETA"\t\t\t              No Event Log.\n");
//            continue;
//        }
//
//        uint32_t hash_size, data_size; 
//        hash_size = get_hash_size(log_descr->alg); 
//        if ( hash_size == 0 )
//            return;
//
//        void *curr, *next;
//
//        curr = (void *)(unsigned long)log_descr->phys_addr + 
//                log_descr->pcr_events_offset;
//        next = (void *)(unsigned long)log_descr->phys_addr +
//                log_descr->next_event_offset;
//        
//        //It is required for each of the non-SHA1 event log the first entry to be the following
//        //TPM1.2 style TCG_PCR_EVENT record specifying type of the log:
//        //TCG_PCR_EVENT.PCRIndex = 0
//        //TCG_PCR_EVENT.EventType = 0x03 // EV_NO_ACTION per TCG EFI
//                                       // Platform specification
//        //TCG_PCR_EVENT.Digest = {00…00} // 20 zeros
//        //TCG_PCR_EVENT.EventDataSize = sizeof(TCG_LOG_DESCRIPTOR).
//        //TCG_PCR_EVENT.EventData = TCG_LOG_DESCRIPTOR
//        //The digest of this record MUST NOT be extended into any PCR.
//
//        if (log_descr->alg != TB_HALG_SHA1){
//            print_event_2(curr, TB_HALG_SHA1);
//            curr += sizeof(tpm12_pcr_event_t) + sizeof(tpm20_log_descr_t);
//        }
//
//        while ( curr < next ) {
//            print_event_2(curr, log_descr->alg);
//            data_size = *(uint32_t *)(curr + 2*sizeof(uint32_t) + hash_size);
//            curr += 3*sizeof(uint32_t) + hash_size + data_size;
//        }
//    }
}


static void print_evt_log_ptr_elt_2_1(const heap_ext_data_element_t *elt)
{
	out_info("ERROR: Printing not supported : heap_ext_data_element_t");
	wait(3000);
//    const heap_event_log_ptr_elt2_1_t *elog_elt = (const heap_event_log_ptr_elt2_1_t *)elt->data;
//   
//    printk(TBOOT_DETA"\t TCG EVENT_LOG_PTR:\n");
//    printk(TBOOT_DETA"\t\t       type: %d\n", elt->type);
//    printk(TBOOT_DETA"\t\t       size: %u\n", elt->size);
//    printk(TBOOT_DETA"\t TCG Event Log Descrption:\n");
//    printk(TBOOT_DETA"\t     allcoated_event_container_size: %u\n", elog_elt->allcoated_event_container_size);
//    printk(TBOOT_DETA"\t                       EventsOffset: [%u,%u]\n", 
//           elog_elt->first_record_offset, elog_elt->next_record_offset);
//
//    if (elog_elt->first_record_offset == elog_elt->next_record_offset) {
//	printk(TBOOT_DETA"\t\t\t No Event Log found.\n");
//	return;
//    }
//    void *curr, *next;
//
//    curr = (void *)(unsigned long)elog_elt->phys_addr + elog_elt->first_record_offset;
//    next = (void *)(unsigned long)elog_elt->phys_addr + elog_elt->next_record_offset;               
//    uint32_t event_header_data_size = print_event_2_1_log_header(curr);
//		
//    curr += sizeof(tcg_pcr_event) + event_header_data_size;
//    while ( curr < next ) {
//	curr += print_event_2_1(curr);
//    }
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


//static void print_bios_data(const bios_data_t *bios_data, uint64_t size)
//{
//    printk(TBOOT_DETA"bios_data (@%p, %jx):\n", bios_data,
//           *((uint64_t *)bios_data - 1));
//    printk(TBOOT_DETA"\t version: %u\n", bios_data->version);
//    printk(TBOOT_DETA"\t bios_sinit_size: 0x%x (%u)\n", bios_data->bios_sinit_size,
//           bios_data->bios_sinit_size);
//    printk(TBOOT_DETA"\t lcp_pd_base: 0x%jx\n", bios_data->lcp_pd_base);
//    printk(TBOOT_DETA"\t lcp_pd_size: 0x%jx (%ju)\n", bios_data->lcp_pd_size,
//           bios_data->lcp_pd_size);
//    printk(TBOOT_DETA"\t num_logical_procs: %u\n", bios_data->num_logical_procs);
//    if ( bios_data->version >= 3 )
//        printk(TBOOT_DETA"\t flags: 0x%08jx\n", bios_data->flags);
//    if ( bios_data->version >= 4 && size > sizeof(*bios_data) + sizeof(size) )
//        print_ext_data_elts(bios_data->ext_data_elts);
//}
//
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

//#ifndef IS_INCLUDED

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
		out_info("OS to MLE data loader context addr field is NULL");
		return 0;
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
//	txt_caps_t sinit_caps;
//	
//    if ( g_tpm->major == TPM20_VER_MAJOR ) {
//		if (g_sinit != NULL) {
//			sinit_caps = get_sinit_capabilities(g_sinit);
//		}
//        if (sinit_caps.tcg_event_log_format) {
//			size[2] = sizeof(os_sinit_data_t) + sizeof(uint64_t) +
//            2 * sizeof(heap_ext_data_element_t) + 
//            sizeof(heap_event_log_ptr_elt2_1_t);
//        }
//		else {
//			u32 count;
//			if ( g_tpm->extpol == TB_EXTPOL_AGILE )
//				count = g_tpm->banks;
//			else 
//				if ( g_tpm->extpol == TB_EXTPOL_EMBEDDED )
//					count = g_tpm->alg_count;
//				else
//					count = 1;
//			size[2] = sizeof(os_sinit_data_t) + sizeof(uint64_t) +
//				2 * sizeof(heap_ext_data_element_t) +
//				4 + count*sizeof(heap_event_log_descr_t);
//		}
//    }

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

//static bool verify_os_sinit_data(const txt_heap_t *txt_heap)
//{
//    uint64_t size, heap_size;
//    os_sinit_data_t *os_sinit_data;
//
//    /* check size */
//    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
//    size = get_os_sinit_data_size(txt_heap);
//    if ( size == 0 ) {
//        printk(TBOOT_ERR"OS to SINIT data size is 0\n");
//        return false;
//    }
//    if ( size > heap_size ) {
//        printk(TBOOT_ERR"OS to SINIT data size is larger than heap size "
//               "(%Lx, heap size=%Lx)\n", size, heap_size);
//        return false;
//    }
//
//    os_sinit_data = get_os_sinit_data_start(txt_heap);
//
//    /* check version (but since we create this, it should always be OK) */
//    if ( os_sinit_data->version < MIN_OS_SINIT_DATA_VER ||
//         os_sinit_data->version > MAX_OS_SINIT_DATA_VER ) {
//        printk(TBOOT_ERR"unsupported OS to SINIT data version (%u)\n",
//               os_sinit_data->version);
//        return false;
//    }
//
//    if ( size != calc_os_sinit_data_size(os_sinit_data->version) ) {
//        printk(TBOOT_ERR"OS to SINIT data size (%Lx) does not match for version (%x)\n",
//               size, sizeof(os_sinit_data_t));
//        return false;
//    }
//
//    if ( os_sinit_data->version >= 6 ) {
//        if ( !verify_ext_data_elts(os_sinit_data->ext_data_elts,
//                                   size - sizeof(*os_sinit_data) - sizeof(size)) )
//            return false;
//    }
//
//    print_os_sinit_data(os_sinit_data);
//
//    return true;
//}
//
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
//
//static void print_sinit_mle_data(const sinit_mle_data_t *sinit_mle_data)
//{
//    printk(TBOOT_DETA"sinit_mle_data (@%p, %Lx):\n", sinit_mle_data,
//           *((uint64_t *)sinit_mle_data - 1));
//    printk(TBOOT_DETA"\t version: %u\n", sinit_mle_data->version);
//    printk(TBOOT_DETA"\t bios_acm_id: \n\t");
//    print_heap_hash(sinit_mle_data->bios_acm_id);
//    printk(TBOOT_DETA"\t edx_senter_flags: 0x%08x\n",
//           sinit_mle_data->edx_senter_flags);
//    printk(TBOOT_DETA"\t mseg_valid: 0x%Lx\n", sinit_mle_data->mseg_valid);
//    printk(TBOOT_DETA"\t sinit_hash:\n\t"); print_heap_hash(sinit_mle_data->sinit_hash);
//    printk(TBOOT_DETA"\t mle_hash:\n\t"); print_heap_hash(sinit_mle_data->mle_hash);
//    printk(TBOOT_DETA"\t stm_hash:\n\t"); print_heap_hash(sinit_mle_data->stm_hash);
//    printk(TBOOT_DETA"\t lcp_policy_hash:\n\t");
//        print_heap_hash(sinit_mle_data->lcp_policy_hash);
//    printk(TBOOT_DETA"\t lcp_policy_control: 0x%08x\n",
//           sinit_mle_data->lcp_policy_control);
//    printk(TBOOT_DETA"\t rlp_wakeup_addr: 0x%x\n", sinit_mle_data->rlp_wakeup_addr);
//    printk(TBOOT_DETA"\t num_mdrs: %u\n", sinit_mle_data->num_mdrs);
//    printk(TBOOT_DETA"\t mdrs_off: 0x%x\n", sinit_mle_data->mdrs_off);
//    printk(TBOOT_DETA"\t num_vtd_dmars: %u\n", sinit_mle_data->num_vtd_dmars);
//    printk(TBOOT_DETA"\t vtd_dmars_off: 0x%x\n", sinit_mle_data->vtd_dmars_off);
//    print_sinit_mdrs((sinit_mdr_t *)
//                     (((void *)sinit_mle_data - sizeof(uint64_t)) +
//                      sinit_mle_data->mdrs_off), sinit_mle_data->num_mdrs);
//    if ( sinit_mle_data->version >= 8 )
//        printk(TBOOT_DETA"\t proc_scrtm_status: 0x%08x\n",
//               sinit_mle_data->proc_scrtm_status);
//    if ( sinit_mle_data->version >= 9 )
//        print_ext_data_elts(sinit_mle_data->ext_data_elts);
//}
//
//static bool verify_sinit_mle_data(const txt_heap_t *txt_heap)
//{
//    uint64_t size, heap_size;
//    sinit_mle_data_t *sinit_mle_data;
//
//    /* check size */
//    heap_size = read_priv_config_reg(TXTCR_HEAP_SIZE);
//    size = get_sinit_mle_data_size(txt_heap);
//    if ( size == 0 ) {
//        printk(TBOOT_ERR"SINIT to MLE data size is 0\n");
//        return false;
//    }
//    if ( size > heap_size ) {
//        printk(TBOOT_ERR"SINIT to MLE data size is larger than heap size\n"
//               "(%Lx, heap size=%Lx)\n", size, heap_size);
//        return false;
//    }
//
//    sinit_mle_data = get_sinit_mle_data_start(txt_heap);
//
//    /* check version */
//    if ( sinit_mle_data->version < 6 ) {
//        printk(TBOOT_ERR"unsupported SINIT to MLE data version (%u)\n",
//               sinit_mle_data->version);
//        return false;
//    }
//    else if ( sinit_mle_data->version > 9 ) {
//        printk(TBOOT_WARN"unsupported SINIT to MLE data version (%u)\n",
//               sinit_mle_data->version);
//    }
//
//    /* this data is generated by SINIT and so is implicitly trustworthy, */
//    /* so we don't need to validate it's fields */
//
//    print_sinit_mle_data(sinit_mle_data);
//
//    return true;
//}
//
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

//    /* verify OS to SINIT data */
//    if ( !verify_os_sinit_data(txt_heap) )
//        return false;
//
//    /* verify SINIT to MLE data */
//    if ( !verify_sinit_mle_data(txt_heap) )
//        return false;
//
	return 1;
}
//
//#endif
//
///*
// * Local variables:
// * mode: C
// * c-basic-offset: 4
// * tab-width: 4
// * indent-tabs-mode: nil
// * End:
// */
