#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>	/* if_nametoindex */
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>	/* inet_ntop */

#include "nuse-hostcalls.h"
#include "nuse-bootp.h"

/* from net/ipconfig.c */

/* packet ops */
#define BOOTP_REQUEST	1
#define BOOTP_REPLY	2

struct bootp_pkt {		/* BOOTP packet format */
	struct ether_header eth;	/* Ethernet header */
	struct iphdr ip;	/* IP header */
	struct udphdr udp;	/* UDP header */
	__u8 op;			/* 1=request, 2=reply */
	__u8 htype;		/* HW address type */
	__u8 hlen;		/* HW address length */
	__u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;	/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;	/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;	/* IP address of BOOTP relay */
	__u8 hw_addr[16];	/* Client's HW address */
	__u8 serv_name[64];     /* Server host name */
	__u8 boot_file[128];    /* Name of boot file */
	__u8 exten[312];	/* DHCP options / BOOTP vendor extensions */
} __attribute__ ((__packed__));


static const __u8 bootp_cookie[4] = { 99, 130, 83, 99 };



static __be32 xid = 0xdeadbeef;		/* XXX: should be randomized */


static int
set_if_promisc(const char *ifname, int val)
{
	int fd;
	struct ifreq ifr;

	if (val)
		val = IFF_PROMISC;
	else
		val = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		printf("failed to get interface status");
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | val;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		printf("failed to set interface to promisc");
		return -1;
	}

	return 0;
}

static uint16_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
	const uint8_t *addr = data;
	uint32_t i;

	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return htons(sum);
}

/* from ipconfig.c */

/*
 *  Process BOOTP extensions.
 */
static void
do_bootp_ext(__u8 *ext, struct bootp_ctx *ctx)
{
	__u8 servers;
	int i;
	__be16 mtu;

	switch (*ext++) {
	case 1:	 /* Subnet mask */
		memcpy(&ctx->netmask, ext+1, 4);
		break;
	case 3:	 /* Default gateway */
		memcpy(&ctx->gateway, ext+1, 4);
		break;

/* XXX: Currently, they are not implemented. */
#if 0
	case 6:	 /* DNS server */
		servers = *ext/4;
		if (servers > CONF_NAMESERVERS_MAX)
			servers = CONF_NAMESERVERS_MAX;
		for (i = 0; i < servers; i++) {
			if (ic_nameservers[i] == NONE)
				memcpy(&ic_nameservers[i], ext+1+4*i, 4);
		}
		break;

	case 12:	/* Host name */
		ic_bootp_string(utsname()->nodename, ext+1, *ext,
				__NEW_UTS_LEN);
		ic_host_name_set = 1;
		break;
	case 15:	/* Domain name (DNS) */
		ic_bootp_string(ic_domain, ext+1, *ext, sizeof(ic_domain));
		break;
	case 17:	/* Root path */
		if (!root_server_path[0])
			ic_bootp_string(root_server_path, ext+1, *ext,
					sizeof(root_server_path));
		break;
	case 26:	/* Interface MTU */
		memcpy(&mtu, ext+1, sizeof(mtu));
		ic_dev_mtu = ntohs(mtu);
		break;
	case 40:	/* NIS Domain name (_not_ DNS) */
		ic_bootp_string(utsname()->domainname, ext+1, *ext,
				__NEW_UTS_LEN);
		break;
#endif
	}
}

static void
bootp_init_ext(__u8 *e)
{
	memcpy(e, bootp_cookie, 4);	/* RFC1048 Magic Cookie */
	e += 4;
	*e++ = 1;		/* Subnet mask request */
	*e++ = 4;
	e += 4;
	*e++ = 3;		/* Default gateway request */
	*e++ = 4;
	e += 4;

#if 0
	*e++ = 5;		/* Name server request */
	*e++ = 8;
	e += 8;
	*e++ = 12;		/* Host name request */
	*e++ = 32;
	e += 32;
	*e++ = 40;		/* NIS Domain name request */
	*e++ = 32;
	e += 32;
	*e++ = 17;		/* Boot path */
	*e++ = 40;
	e += 40;

	*e++ = 57;		/* set extension buffer size for reply */
	*e++ = 2;
	*e++ = 1;		/* 128+236+8+20+14, see dhcpd sources */
	*e++ = 150;
#endif
	*e++ = 255;		/* End of the list */
}

static unsigned
int if_nametoindex_on_nuse(const char *ifname)
{
	int index;
	int ctl_sock;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	index = 0;
	ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctl_sock >= 0) {
		if (ioctl(ctl_sock, SIOCGIFINDEX, &ifr) >= 0)
			index = ifr.ifr_ifindex;
		close(ctl_sock);
	}

	return index;
}

int
nuse_bootp_ctx_init(struct bootp_ctx *ctx, char *ifname)
{
	int fd, err, sock;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	/* open raw socket through nuse */
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex_on_nuse(ifname);
	ll.sll_protocol = htons(ETH_P_ALL);
	err = bind(sock, (struct sockaddr *)&ll, sizeof(ll));
	if (err < 0) {
		printf("index is %d\n", ll.sll_ifindex);
		perror("bind");
		return 0;
	}

	/* get mac address */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		return 0;
	}
	close(fd);

	/* setup bootp_ctx */
	memset(ctx, 0, sizeof(struct bootp_ctx));
	memcpy(ctx->ifname, ifname, IFNAMSIZ);
	memcpy(ctx->haddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	ctx->sock = sock;
	ctx->xid = htonl(xid);	/* XXX: should be randamized */

	return 1;
}


static int
nuse_bootp_send_request(struct bootp_ctx *ctx)
{
	int ret;
	struct iphdr *ip;
	struct udphdr *udp;
	struct bootp_pkt b;
	__u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	printf("sending bootp request for %s.\n", ctx->ifname);

	memset(&b, 0, sizeof(b));

	/* fill ether header */
	memcpy(b.eth.ether_dhost, bcast, ETH_ALEN);
	memcpy(b.eth.ether_shost, ctx->haddr, ETH_ALEN);
	b.eth.ether_type = htons(ETHERTYPE_IP);

	/* fill ip header */
	ip = &b.ip;
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(sizeof(struct bootp_pkt)
			    - sizeof(struct ether_header));
	ip->frag_off = htons(IP_DF);
	ip->ttl = 16;
	ip->protocol = IPPROTO_UDP;
	ip->daddr = htonl(INADDR_BROADCAST);
	ip->check = wrapsum(checksum(ip, sizeof(*ip), 0));

	/* fill udp header */
	udp = &b.udp;
	udp->source = htons(68);
	udp->dest = htons(67);
	udp->len = htons((sizeof(struct bootp_pkt) - sizeof(struct iphdr)
			  - sizeof(struct ether_header)));
	udp->check = 0;		/* no checksum */

	/* fill bootp header */
	b.op = BOOTP_REQUEST;
	b.htype = ARPHRD_ETHER;
	b.hlen = ETH_ALEN;
	b.xid = ctx->xid;
	b.secs = 1;	/* XXX */
	memcpy(b.hw_addr, ctx->haddr, ETH_ALEN);

	/* set bootp option request */
	bootp_init_ext(b.exten);

	ret = write(ctx->sock, &b, sizeof(b));
	return ret;
}

static int
nuse_bootp_recv_reply(struct bootp_ctx *ctx)
{
	int ret;
	int timeout = 10;	/* default timeout 10 sec */
	char buf[1024];
	time_t before, after;
	struct bootp_pkt *b;
	struct pollfd x[1];

	x[0].fd = ctx->sock;
	x[0].events = POLLIN;

	before = time(NULL);

	printf("waiting bootp reply\n");

	for (;;) {

		if (poll(x, 1, 1) == 0) {
			printf(".");
			fflush(stdout);
			after = time(NULL);
			if ((after - before) > timeout) {
				printf("timeout!!");
				break;
			}
		}

		ret = read(ctx->sock, buf, sizeof(buf));
		if (ret < 0) {
			printf("\n");
			perror("read");
			return ret;
		}

		b = (struct bootp_pkt *)buf;

		/* is bootp reply packet for me ? */
		if (b->udp.source != htons(67) || b->udp.dest != htons(68) ||
		    b->op != BOOTP_REPLY || b->xid != xid ||
		    memcmp(ctx->haddr, b->hw_addr, ETH_ALEN) != 0)
			continue;

		/* record my ip */
		ctx->address = b->your_ip;

		/* ok, parse it */
		do_bootp_ext(b->exten, ctx);
	}

	printf("\n");

	return 1;
}


int
nuse_bootp_start(struct bootp_ctx *ctx)
{
	int ret;
	char addr[16], mask[16], gate[16];

	set_if_promisc(ctx->ifname, 1);

	ret = nuse_bootp_send_request(ctx);
	if (ret < 0)
		return ret;

	ret = nuse_bootp_recv_reply(ctx);

	close(ctx->sock);

	if (ret < 1)
		return ret;

	inet_ntop(AF_INET, &ctx->address, addr, sizeof(addr));
	inet_ntop(AF_INET, &ctx->netmask, mask, sizeof(mask));
	inet_ntop(AF_INET, &ctx->gateway, gate, sizeof(gate));

	printf("%s DHCP done\n", ctx->ifname);
	printf("ADDRESS: %s\n", addr);
	printf("NETMASK: %s\n", mask);
	printf("GATEWAY: %s\n", gate);

	set_if_promisc(ctx->ifname, 0);

	return ret;
}
