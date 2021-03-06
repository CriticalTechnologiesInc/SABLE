/*
 * errors.c: parse and return status of Intel(r) TXT error codes
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

#include "types.h"
#include "config_regs.h"
#include "errorcode.h"
#include "util.h"

int txt_has_error(void)
{
	txt_errorcode_t err;

	err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
	if (err._raw == 0 || err._raw == 0xc0000001 || err._raw == 0xc0000009) {
		return 0;
	} 
	else {   
		return 1;
	}
}

void txt_display_errors(void)
{
	txt_errorcode_t err;
	txt_ests_t ests;
	txt_e2sts_t e2sts;
	txt_errorcode_sw_t sw_err;
	acmod_error_t acmod_err;

	/*
	 * display TXT.ERRORODE error
	 */

	err = (txt_errorcode_t)read_pub_config_reg(TXTCR_ERRORCODE);
	if (txt_has_error() != 0) {
		out_info("ERROR : Need attention");
	}
        #ifndef NDEBUG
	out_description64("TXT.ERRORCODE ", err._raw);
	#endif

	/* AC module error (don't know how to parse other errors) */
	if (err.valid) {
		if (err.external == 0) {	/* processor error */
			out_description("processor error", (uint32_t)err.type);
		} else {			/* external SW error */
			sw_err._raw = err.type;
			if (sw_err.src == 1) {/* unknown SW error */
				out_info("unknown SW error");
				out_description("sw_err.err1", sw_err.err1);
				out_description("sw_err.err2", sw_err.err2);
			} else {                     /* ACM error */
				acmod_err._raw = sw_err._raw;
				if (!(acmod_err._raw == 0x0 || acmod_err._raw == 0x1 || acmod_err._raw == 0x9)) {
					out_info("ERROR DETECTED");
				}
				out_info("AC module error info:");
				out_description("acm_type:", acmod_err.acm_type);
				out_description("progress", acmod_err.progress);
				out_description("error", acmod_err.error);
				/* error = 0x0a, progress = 0x0d => TPM error */
				if (acmod_err.error == 0x0a && acmod_err.progress == 0x0d) {
					out_description("TPM error code = 0x%x\n", acmod_err.tpm_err);
				}
				/* progress = 0x10 => LCP2 error */
				else if (acmod_err.progress == 0x10 && acmod_err.lcp_minor != 0) {
					out_info("LCP2 error:");
					out_description("minor error", acmod_err.lcp_minor);
					out_description("index", acmod_err.lcp_index);
				}
			}
		}
	}

	/*
	 * display TXT.ESTS error
	 */

	ests = (txt_ests_t)read_pub_config_reg(TXTCR_ESTS);
	if (!(ests._raw == 0)) {
		out_info("ERROR : need attention");
	}
	#ifndef NDEBUG
	out_description64("TXT.ESTS:", ests._raw);
	#endif

	/*
	 * display TXT.E2STS error
	 */

	e2sts = (txt_e2sts_t)read_pub_config_reg(TXTCR_E2STS);
	if (!(e2sts._raw == 0 || e2sts._raw == 0x200000000)) {
		out_info("ERROR : need attention");
	}
	#ifndef NDEBUG
	out_description64("TXT.E2STS", e2sts._raw);
	wait(3000);
	#endif
}
