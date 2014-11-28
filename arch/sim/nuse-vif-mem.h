#ifndef _NUSE_VIF_MEM_H_
#define _NUSE_VIF_MEM_H_

/* called by nuse process. not applications */

void * vifmem_open(char *ifname);
void vifmem_close(void * vif);

int vifmem_write(void *vif, const void *buf, size_t len);
int vifmem_read(void *vif, void *buf, size_t len);


#endif /* _NUSE_VIF_MEM_H_ */
