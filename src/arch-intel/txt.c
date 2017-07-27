#include "types.h"
#include "smx.h"
#include "processor.h"
#include "util.h"

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
	out_info("Remove this code : SMX is enabled");

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
		}
		else {
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
