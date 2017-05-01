#define		_GNU_SOURCE
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/mman.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<dlfcn.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>

typedef int (*SOCKET)(int domain, int type, int protocol);

unsigned int imagebase = 0x56555000;
unsigned int hooked;

void	hook_code();

unsigned int  raw_data_cpuid_len = 43;
unsigned char raw_data_cpuid[] = {
        0x55, 0x89, 0xe5, 0x56, 0x8b, 0x75, 0x08, 0x53, 0xb8, 0x07, 
        0x00, 0x00, 0x00, 0x0f, 0xa2, 0x89, 0x1e, 0x89, 0x4e, 0x04, 
        0x89, 0x56, 0x08, 0x31, 0xc0, 0x40, 0x0f, 0xa2, 0x89, 0x4e, 
        0x0c, 0x89, 0x56, 0x10, 0x5b, 0xb8, 0x18, 0x00, 0x00, 0x00, 
        0x5e, 0x5d, 0xc3, 
};

unsigned char raw_data_cpuid_fake[] = {
        0x55, 0x89, 0xe5, 0x56, 0x8b, 0x75, 0x08, 0x53, 
	0xc7, 0x46, 0x0c, 0xbf, 0xe3, 0xba, 0x7f, 0xc7, 0x46, 0x10, 
        0xff, 0xfb, 0xeb, 0xbf, 0xc7, 0x06, 0x00, 0x00, 0x00, 0x00, 
        0xc7, 0x46, 0x04, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x46, 0x08, 
        0x00, 0x00, 0x00, 0x00, 
	0x5b, 0xb8, 0x18, 0x00, 0x00, 0x00, 0x5e, 0x5d, 0xc3, 
};


void *memcmp_pattern(void *data, size_t len, void *pattern, size_t lenpattern){
	unsigned char *d = (unsigned char *)data;
	
	while (len - lenpattern != 0){
		if (!memcmp(d, pattern, lenpattern)){
			return d;
		}
		d++;
		len --;

	}
	return NULL;
}

int	count = 0;

void	hook_function(void *data){
	void *buff = data;
	char	fname[1024];
	int	fd;
	unsigned char *p;

	memset(fname, 0, sizeof(fname));
	sprintf(fname, "/home/user/Desktop/dump%d.bin", count++);
	fd = open(fname, O_RDWR | O_CREAT, 0755);
	write(fd, data, 0x2000);
	close(fd);
	printf("dumping : %s\n", fname);
	buff = memcmp_pattern(data, 0x2000, (void *)"/proc/bus/pci/devices", strlen("/proc/bus/pci/devices"));
	if (buff){
		printf("Found virtualization... %s\n", (char *)buff);
		memcpy(buff, "/home/user/devices", strlen("/home/user/devices")+1);
		printf("replaced		%s\n", (char *)buff);
	}
	
	if (!memcmp(data, raw_data_cpuid, raw_data_cpuid_len)){
		memcpy(data, raw_data_cpuid_fake, sizeof(raw_data_cpuid_fake));
		printf("patched cpuid\n");


	}

	printf("Executing code... at %p\n", data);
	if (count == 8){
		p = (unsigned char *)(imagebase + 0x92d);
		p[0] = 0xFF;
		p[1] = 0x95;
		p[2] = 0xD8;
		p[3] = 0xEF;
		p[4] = 0xFF;
		p[5] = 0xFF;
		//while (1){}	
//	FF 95 D8 EF FF FF
	}
	
}

int socket(int domain, int type, int protocol){
	SOCKET fnsocket = dlsym(RTLD_NEXT, "socket");
	unsigned char *detour;
	unsigned char *oldbytes;
	unsigned char *data;
	
	if (hooked == 0){
		hooked = 1;
		detour = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		oldbytes = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		mprotect((void *)imagebase, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE);
	
		data = (unsigned char *)(imagebase + 0x92d);
		data[0] = 0x68;
		*(unsigned int *)&data[1] = hook_code;
		data[5] = 0xC3;		

	}
	
	return fnsocket(domain, type, protocol);

}
