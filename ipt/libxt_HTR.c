#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>

#include "../htr/xt_HTR.h"

enum {
	O_HTR_HOST = 0,
};

static void htr_help(void)
{
	printf(
		"HTR action options:\n"
		"  --host hostname\n"
	);
}

static const struct xt_option_entry htr_opts[] = {
	{
		.name = "host",
		.id = O_HTR_HOST,
		.type = XTTYPE_STRING,
		.size = MAX_HOSTNAME_LEN,
		.flags = XTOPT_PUT, XTOPT_POINTER(struct xt_htr_info, host),
	},
	XTOPT_TABLEEND,
};

static void htr_parse(struct xt_option_call *cb)
{
	struct xt_htr_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_HTR_HOST:
			info->op_flags |= XT_HTR_OP_HOST;
			break;
	}
}

static void htr_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM, "HTR: no option specified");
}

static void htr_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_htr_info *info = (const struct xt_htr_info *)match->data;
	printf(" HTR to %s", info->host);
}

static void htr_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_htr_info *info = (const struct xt_htr_info *)match->data;
	if (info->op_flags & XT_HTR_OP_HOST) {
	    printf("--host %s", info->host);
	}//if
}

static struct xtables_target htr_target = {
    .name           = "HTR",
    .version        = XTABLES_VERSION,
    .family         = NFPROTO_IPV4,
    .revision       = 1,
    .size           = XT_ALIGN(sizeof(struct xt_htr_info)),
    .userspacesize  = XT_ALIGN(sizeof(struct xt_htr_info)),
    .help           = htr_help,
    .print          = htr_print,
    .save           = htr_save,
    .x6_parse       = htr_parse,
    .x6_fcheck      = htr_check,
    .x6_options     = htr_opts,
};

void _init(void)
{
    xtables_register_target(&htr_target);
}
