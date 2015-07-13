/* simulator -- launcher daemon */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <err.h>
#include <grp.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

pid_t launch_dump_process(char * ts, char *fn){
	pid_t pid;
    char *argv[32] = {0};
    switch ((pid = fork()))
    {
    case -1: /* error */
        fprintf(stdout, "fork error!");
    case 0:  /* child */
        break;
    default: /* parent */
        /*fprintf(stdout,"%s: pid %d", name, pid); */
        return pid;
    }
    
    /* child */
    argv[0] = "./dump_process";
    argv[1] = ts;
    argv[2] = fn;
    execv(argv[0], argv);
    fprintf(stderr, "You can never go here: execv %s ...", argv[0]);
    return pid;
}

pid_t launch_visitWeb_process(){
	pid_t pid;
    char *argv[32] = {0};
    switch ((pid = fork()))
    {
    case -1: /* error */
        fprintf(stdout, "fork error!");
    case 0:  /* child */
        break;
    default: /* parent */
        /*fprintf(stdout,"%s: pid %d", name, pid); */
        return pid;
    }
    
    /* child */
    argv[0] = "./visitWebPages.sh";
    execv(argv[0], argv);
    fprintf(stderr, "You can never go here: execv %s ...", argv[0]);
    return pid;
}

int main(int argc, char **argv){
    if (argc != 3){
    	fprintf(stdout,"Usage: %s arg1 arg2\n", argv[0]);
    	fprintf(stdout, "arg1: time_interval(specified in seconds, at least 5)\n");
    	fprintf(stdout, "arg2: output dump file(say, dump.pcap)\n");
	exit(0);
    }

	if(access(argv[2], F_OK) != -1){
		fprintf(stdout, "Note that the output dump file \"%s\" already exists. It will be overwritten.", argv[2]);
		unlink(argv[2]);
	}
	
	pid_t pid_dump = launch_dump_process(argv[1], argv[2]);
	sleep(5);
	pid_t pid_visitWeb = launch_visitWeb_process();
	waitpid(pid_visitWeb, NULL, 0);
	waitpid(pid_dump, NULL, 0);
    exit(0); 
}












