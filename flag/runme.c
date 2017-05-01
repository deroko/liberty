#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/mman.h>
#include	<sys/stat.h>
#include	<sys/types.h>
#include	<fcntl.h>

typedef unsigned int (*GETMODS)(int counter);

int main(){
	int	fd;
	struct	stat	st;
	GETMODS 	getrandom;
	void		*buff;
	unsigned	int rnd;
	unsigned	int	index;


	fd = open("knock.bin", O_RDONLY);
	fstat(fd, &st);

	buff = mmap(0, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	read(fd, buff, st.st_size);		

	getrandom = (GETMODS)buff;
	for (index = 0; index < 0x20; index++)
		printf("%.02X", getrandom(index]));
}
