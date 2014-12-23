#ifndef _NUSE_BOOTP_H_
#define _NUSE_BOOTP_H_

#include <linux/if_ether.h>	/* ETH_ALEN */

struct bootp_ctx {

	__be32	address;	/* IP address for client	*/
	__be32	netmask;	/* netmask for address	*/
	__be32	gateway;	/* default gateway	*/


	/* private */
	int sock;
	char ifname[IFNAMSIZ];
	__be32	xid;
	__u8	haddr[ETH_ALEN];
};

int nuse_bootp_ctx_init(struct bootp_ctx *ctx, char *ifname);
int nuse_bootp_start(struct bootp_ctx *ctx);



#endif /* _NUSE_BOOTP_H_ */
