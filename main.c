#include <sys/ptrace.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>

const long RSAPTR = 0x82bf200;
const int RSALEN = 310;
const char RSA_KEY[] = "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413";

const long HOSTNAMEPTR = 0x84dc6bc;

const int LEN = 32;

pid_t findPid(char* name);
int readMemory(pid_t pid, long addr, char *data, unsigned size);
int writeMemory(pid_t pid, long addr, char *data, unsigned size);
int chartohex(unsigned char *data);

int main(int argc, char** argv)
{
	pid_t pid = findPid("Tibia");

	printf("Tibia pid: %d\n", pid);

	
	char data[310] = "";
	strcpy(data, RSA_KEY);
	writeMemory(pid, RSAPTR, data, RSALEN);
	
	readMemory(pid, RSAPTR, data, RSALEN);
	
	unsigned char ptrdata[4] = "";
	readMemory(pid, HOSTNAMEPTR, ptrdata, 4);

	readMemory(pid, chartohex(ptrdata)+4, ptrdata, 4);
	char loc[255] = "";
   	strcpy(loc,argv[1]);
	int len = 255;
	writeMemory(pid, chartohex(ptrdata), loc, 26); 

	readMemory(pid,chartohex(ptrdata), data, 26);
	printf("IP changed to: %s\n", data);

	return 1;
}

int chartohex(unsigned char *data)
{
	int ret = 0;
	int i;
	for(i = 0; i < 4; i++)
		ret += (int)data[i]*pow(16,i*2);

	return ret;
}

pid_t findPid(char* name)
{
	char command[80] = "";
	strcpy(command, "pidof ");
	strcat(command,name);
	char line[LEN];
	FILE *cmd = popen(command, "r");
	fgets(line, LEN, cmd);
	pid_t pid = strtoul(line, NULL, 10);
	pclose(cmd);
	return pid;
}

int readMemory(pid_t pid, long addr, char *data, unsigned size)
{
	if(ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		fprintf(stderr, "error: failed to attach to %d, %s\n", pid, strerror(errno));
	}


	wait(0);

	int i;
	for(i = 0;i<size;i+=sizeof(int)){
		int buff;
		buff = ptrace(PTRACE_PEEKDATA, pid, addr+i, 0);
		memcpy(data+i, &buff, sizeof(int));
	}

	if(ptrace(PTRACE_DETACH, pid, 0, 0)!=0)
		return -1;

	return 1;
}

int writeMemory(pid_t pid, long addr, char *data, unsigned size)
{
	if(ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		fprintf(stderr, "error: failed to attach to %d, %s\n", pid, strerror(errno));
	}

	wait(NULL);

	int i;
	for(i=0;i<size;i+=sizeof(int)){
		int buff;
		memcpy(&buff, data+i, sizeof(int));
		ptrace(PTRACE_POKEDATA, pid, addr+i, buff);
	}

	if(ptrace(PTRACE_DETACH, pid, 0, 0)!=0)
		return -1;

	return 1;
}

