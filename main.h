#include <sys/ptrace.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>

const long RSAPTR37 = 0x82bf200;
const long HOSTNAMEPTR37 = 0x84dc6bc;

const long RSAPTR31 = 0x83b0b00;
const long HOSTNAMEPTR31 = 0x85fa59c;

const int RSALEN = 310;
const char RSA_KEY[] = "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413";
const int LEN = 32;
const char TIBIA_PATH[] = "Tibia";//"/home/jonas/Documents/Games/Tibia/10.31/Tibia";
//const char TIBIA_ENV[] = "/home/jonas/Documents/Games/Tibia/10.31/";

int readMemory(pid_t pid, long addr, char *data, unsigned size);
int writeMemory(pid_t pid, long addr, char *data, unsigned size);
int chartohex(unsigned char *data);
void fatal(char *msg);
void usage();
long getRSAPointer(char *version);
long getHostPointer(char *version);