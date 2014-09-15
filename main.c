#include "main.h"

int main(int argc, char** argv)
{
	if(argc < 3)
		usage();

	long rsaptr = getRSAPointer(argv[1]);
	long hostptr = getHostPointer(argv[1]);

	printf("%lo   %lo", rsaptr, hostptr);

	int childpid = fork();
	if(childpid == -1)
		fatal("Unable to fork.");

	if(childpid == 0)
	{
		printf("I'm the child");
		//chdir(TIBIA_ENV);
		execl(TIBIA_PATH, (const char*) NULL, (char*) NULL);
		exit(0);
	}

	sleep(2);
	pid_t pid = findPid("Tibia");

	//write RSA key
	char data[310] = "";
	strcpy(data, RSA_KEY);
	writeMemory(pid, rsaptr, data, RSALEN);
	
	//DEBUG
	readMemory(pid, rsaptr, data, RSALEN);
	printf("rsa: %s\n", data);
	//DEBUG
	
	//read pointer to Hostname struct
	unsigned char ptrdata[4] = "";
	readMemory(pid, hostptr, ptrdata, 4);

	//read offset+4 on Hostname struct
	readMemory(pid, chartohex(ptrdata)+4, ptrdata, 4);
	char loc[26] = "";
   	strcpy(loc,argv[2]);
	int len = 26;
	writeMemory(pid, chartohex(ptrdata), loc, len); 

	readMemory(pid,chartohex(ptrdata), data, 30);
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
	if(pid == 0)
		fatal("Could not find Tibia process");
	return pid;
}

int readMemory(pid_t pid, long addr, char *data, unsigned size)
{
	if(ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		fatal("Could not attach to Tibia process. Try running this program as root");
	}

	wait(NULL);

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
		fatal("Could not attach to Tibia. Try running this program as root");
	}

	wait(NULL);

	int i;
	for(i=0;i<size;i+=sizeof(int)){
		int buff;
		memcpy(&buff, data+i, sizeof(int));
		ptrace(PTRACE_POKEDATA, pid, addr+i, buff);
	}

	if(ptrace(PTRACE_DETACH, pid, 0, 0)!=0)
		fatal("Could not detach from Tibia process. Try running this program as root");

	return 1;
}

void fatal(char *msg)
{
	printf("Fatal error: %s\n", msg);
	exit(0);
}

void usage()
{
	printf("Usage: ipchanger [version] [IP]\n");
	exit(0);
}

long getRSAPointer(char *version)
{
	if(strcmp(version,"10.31") == 0)
		return RSAPTR31;
	if(strcmp(version,"10.37") == 0)
		return RSAPTR37;
	fatal("Version not supported.");
	return (long)NULL;
}

long getHostPointer(char *version) {
	if(strcmp(version,"10.31") == 0)
		return HOSTNAMEPTR31;
	if(strcmp(version,"10.37") == 0)
		return HOSTNAMEPTR37;
	fatal("Version not supported.");
	return (long)NULL;
}