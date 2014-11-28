#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "sim-types.h"
#include "sim-assert.h"
#include "nuse-vif.h"
#include "nuse-vif-mem.h"


typedef int (*initcall_t)(void);
#define __define_initcall(fn, id)                                       \
	static initcall_t __initcall_ ## fn ## id                       \
	__attribute__((__section__(".initcall" #id ".init"))) = fn;

#define VIFMEM_MAX	16
#define VIFMEM_BUFLEN	2048

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif

struct nuse_vif_mem_buf {

	pthread_cond_t	cond;
	pthread_mutex_t	mutex;

	/* XXX: should be iovec ? */
	int len;
	char pkt[VIFMEM_BUFLEN];
};

struct nuse_vif_mem {
	char ifname[IFNAMSIZ];
	struct nuse_vif_mem_buf tx, rx;
};


static struct nuse_vif_mem *vifmems[VIFMEM_MAX] = { 
	[0 ... VIFMEM_MAX - 1] = NULL
};


extern struct SimDevicePacket sim_dev_create_packet(struct SimDevice *dev,
						    int size);
extern void sim_dev_rx(struct SimDevice *device,
		       struct SimDevicePacket packet);
extern void sim_softirq_wakeup(void);
extern void *sim_malloc(unsigned long size);
extern void *sim_free(void *buffer);

void
nuse_vif_mem_read(struct nuse_vif *vif, struct SimDevice *dev)
{
	struct nuse_vif_mem * mem = vif->private;

	pthread_mutex_lock(&mem->rx.mutex);

	while (1) {
		pthread_cond_wait(&mem->rx.cond, &mem->rx.mutex);
		
		struct SimDevicePacket packet =
			sim_dev_create_packet(dev, mem->rx.len);
		memcpy(packet.buffer, mem->rx.pkt, mem->rx.len);
		sim_dev_rx(dev, packet);
		sim_softirq_wakeup();
	}
}

void
nuse_vif_mem_write(struct nuse_vif *vif, struct SimDevice *dev,
		   unsigned char *data, int len)
{
	/* nuse stack to application */
	int ret;
	struct nuse_vif_mem * mem = vif->private;

	if ((ret = pthread_mutex_trylock(&mem->tx.mutex)) != 0) {
		return;
	}
	
	pthread_mutex_lock(&mem->tx.mutex);

	mem->tx.len = len;
	memcpy(mem->tx.pkt, data, len);

	pthread_mutex_unlock(&mem->tx.mutex);
	pthread_cond_signal(&mem->tx.cond);
}

void *
nuse_vif_mem_create(const char *ifname)
{
	int n;
	struct nuse_vif * vif;
	struct nuse_vif_mem * mem;

	mem = (struct nuse_vif_mem *) sim_malloc(sizeof (*mem));
	memset(mem, 0, sizeof (*mem));
	strncpy (mem->ifname, ifname, IFNAMSIZ);

	vif = sim_malloc(sizeof (*vif));
	memset (vif, 0, sizeof (*vif));
	vif->private = mem;

	pthread_cond_init(&mem->tx.cond, NULL);
	pthread_cond_init(&mem->rx.cond, NULL);
	pthread_mutex_init(&mem->tx.mutex, NULL);
	pthread_mutex_init(&mem->rx.mutex, NULL);

	for (n = 0; vifmems[n] != NULL && n < VIFMEM_MAX; n++);
	if (n == VIFMEM_MAX) {
		printf("max num of viftype mem is %d\n", VIFMEM_MAX);
		sim_assert(0);
	}
		
	vifmems[n] = mem;

	return vif;
}

void
nuse_vif_mem_delete(struct nuse_vif *vif)
{
	struct nuse_vif_mem * mem = vif->private;

	pthread_cond_destroy(&mem->tx.cond);
	pthread_cond_destroy(&mem->rx.cond);
	pthread_mutex_destroy(&mem->tx.mutex);
	pthread_mutex_destroy(&mem->rx.mutex);

	sim_free(mem);
	sim_free(vif);
}

void *
vifmem_open(char *ifname)
{
	int n;

	for (n = 0; n < VIFMEM_MAX; n++) {
		if (strncmp(ifname, vifmems[n]->ifname, IFNAMSIZ) == 0) {
			return (void *)vifmems[n];
		}
	}

	return NULL;
}

void
vifmem_close(void * vif)
{
	/* XXX: nothing to do ? */
	return;
}

int
vifmem_write(void *vif, const void *buf, size_t len)
{
	/* process to nuse stack via mem vif */	
	int ret;
	struct nuse_vif_mem * mem = vif;

	if ((ret = pthread_mutex_trylock(&mem->rx.mutex)) != 0) {
		printf ("faield to get mutex to write %d\n", ret);
		return ret;
	}

	pthread_mutex_lock(&mem->rx.mutex);
	
	memcpy(mem->rx.pkt, buf, len);
	mem->rx.len = len;

	pthread_mutex_unlock(&mem->rx.mutex);
	pthread_cond_signal(&mem->rx.cond);

	return len;
}

int
vifmem_read(void *vif, void *buf, size_t len)
{
	/* nuse stack to process via mem vif */
	int nbytes;
	struct nuse_vif_mem * mem = vif;

	pthread_mutex_lock(&mem->tx.mutex);
	pthread_cond_wait(&mem->tx.cond, &mem->tx.mutex);

	nbytes = (len > mem->tx.len) ? mem->tx.len : len;
	memcpy(buf, mem->tx.pkt, nbytes);

	return nbytes;
}

static struct nuse_vif_impl nuse_vif_mem = {
	.read	= nuse_vif_mem_read,
	.write	= nuse_vif_mem_write,
	.create	= nuse_vif_mem_create,
	.delete	= nuse_vif_mem_delete,
};

extern struct nuse_vif_impl *nuse_vif[NUSE_VIF_MAX];

int 
nuse_vif_mem_init(void)
{
	nuse_vif[NUSE_VIF_MEM] = &nuse_vif_mem;
	return 0;
}
__define_initcall(nuse_vif_mem_init, 1);
