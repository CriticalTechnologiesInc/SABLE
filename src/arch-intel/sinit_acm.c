#include "types.h"
#include "uuid.h"
#include "config.h"
#include "mle.h"
#include "acmod.h"
#include "mbi.h"
#include "util.h"

__data acm_hdr_t *g_sinit = 0;



struct module *get_module_mb1(struct mbi *m, unsigned int i)
{
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
	out_description("Bhushan: prepare_sinit : ", m->mods_count);
	for ( unsigned int i = (m->mods_count) - 1; i > 0; i-- ) {
		struct module *mod = get_module_mb1(m, i);
		out_string("Working on module :\n");
		out_string((const char *)mod->string);
	}
	return 1;
}
