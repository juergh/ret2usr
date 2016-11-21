struct ret2usr_req {
	unsigned long user_addr;
	unsigned long phys_addr;
	unsigned long kern_addr;
	int len;
	char data[1024];
	int status;
};

#define RET2USR_BASE	'R'
#define RET2USR_READ	_IOWR(RET2USR_BASE, 0, struct ret2usr_req)
#define RET2DIR_READ	_IOWR(RET2USR_BASE, 1, struct ret2usr_req)
#define RET2USR_EXEC	_IOWR(RET2USR_BASE, 2, struct ret2usr_req)
#define RET2DIR_EXEC	_IOWR(RET2USR_BASE, 3, struct ret2usr_req)
