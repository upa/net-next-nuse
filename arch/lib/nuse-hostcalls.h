#ifndef NUSE_HOSTCALLS_H
#define NUSE_HOSTCALLS_H

struct pollfd;
struct pthread;
struct pthread_attr;
typedef unsigned long int pthread_t;

/* nuse-hostcalls.c */
void nuse_hostcall_init(void);

extern int (*host_socket)(int fd, int type, int proto);
extern int (*host_close)(int fd);
extern int (*host_bind)(int, const struct sockaddr *, int);
extern ssize_t (*host_read)(int fd, void *buf, size_t count);
extern ssize_t (*host_write)(int fd, const void *buf, size_t count);
extern ssize_t (*host_writev)(int fd, const struct iovec *iovec, size_t count);
extern int (*host_open)(const char *pathname, int flags,...);
extern int (*host_open64)(const char *pathname, int flags,...);
extern int (*host_ioctl)(int d, int request, ...);
extern int (*host_pipe)(int pipefd[2]);
extern int (*host_poll)(struct pollfd *, int, int);
extern int (*host_pthread_create)(pthread_t *, const struct pthread_attr *,
				  void *(*)(void *), void *);
extern int (*host_pthread_join)(pthread_t thread, void **retval);
extern char *(*host_getenv)(const char *name);
extern FILE *(*host_fdopen)(int fd, const char *mode);
extern int (*host_fcntl)(int fd, int cmd, ... /* arg */ );
extern int (*host_fclose)(FILE *fp);
extern size_t (*host_fwrite)(const void *ptr, size_t size, size_t nmemb,
                        FILE *stream);
extern int (*host_access)(const char *pathname, int mode);

#endif /* NUSE_HOSTCALLS_H */
