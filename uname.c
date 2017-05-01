#include	<stdio.h>
#include 	<sys/types.h>
#include 	<unistd.h>
#include	<fcntl.h>
#include	<string.h>

int main(int argc, char **argv){
	pid_t ppid;
	char	data[1024];
	char	link[1024];
	ppid = getppid();
	memset(data, 0, sizeof(data));
	sprintf(data, "/proc/%d/exe", ppid);
	memset(link, 0, sizeof(link));
	readlink(data, link, sizeof(link));
	if (strstr(link, "liberty")){
		printf("4.11.0-rc8\n");
		return 0;
	}

	argv[0] = "/bin/uname_old";
	execve(argv[0], argv, NULL);
	
	//printf("4.11.0-041100rc5-generic\n");
}
