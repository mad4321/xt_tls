#ifndef _XT_HTR_TARGET_H
#define _XT_HTR_TARGET_H

#define XT_HTR_OP_HOST   0x01

#define MAX_HOSTNAME_LEN 255

/* target info */
struct xt_htr_info {
        __u16 op_flags;
	char host[MAX_HOSTNAME_LEN + 1];
};

#endif /* _XT_HTR_TARGET_H */
