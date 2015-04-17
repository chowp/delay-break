#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <ctype.h>
#include "ieee80211_radiotap.h"
#include "ieee80211.h"
#include "hello.h"
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>
//#include <time.h>
#include <string.h>


#define __STDC_FORMAT_MACROS
#include <inttypes.h>
//#include "util.h"
/* Set of signals that get blocked while processing a packet. */
sigset_t block_set;

#define PCAP_TIMEOUT_MILLISECONDS 1000
#define PCAP_PROMISCUOUS 0
#define QUEUE_SIZE 0
#define IPV6 40
#define false 0
#define true 1

#define DUMP_DIR "/tmp/wifiunion-passive/w111.cap"
#define PENDING_UPDATE_FILENAME "/tmp/wifiunion-passive/current-update.gz"
#define PENDING_FREQUENT_UPDATE_FILENAME_DELAY_WIRE "/tmp/wifiunion-passive/update-delay-wire"
#define UPDATE_FILENAME "/tmp/wifiunion-uploads/passive/%s-%" PRIu64 "-%d.gz"
#define FREQUENT_UPDATE_FILENAME "/tmp/wifiunion-uploads/%s/wire_data/%s-%d-%d"
#define UPLOAD_FAILURES_FILENAME "/tmp/wifiunion-data-transmit-failures.log"
//#define FREQUENT_UPDATE_PERIOD_SE  CONDS 30
#define NUM_MICROS_PER_SECOND 1e6
#define NUM_NANO_PER_SECOND   1e9
static int hold[HOLD_TIME];
static int FREQUENT_UPDATE_PERIOD_SECONDS;
static int FREQUENT_UPDATE_DELAY_SECONDS;

static unsigned char bismark_id[MAC_LEN];
static char mac[12];
static char mac_zero[12] = "000000000000";
static char mac_ffff[12] = "FFFFFFFFFFFF";
static int frequent_sequence_number = 0;
static int64_t start_timestamp_microseconds;
static int begin_time = 0;
static int now_time = 0;
static int last_time = 0;
static int debug;
static int rp = 0;
static int rpp = 0;
static int every = 0;
static int pch_count_debug = 0;
static double time_pch;
static int last_drop = 0;

struct packet_info store[HOLD_TIME]; /* used to store neighbor's info */
struct inf_info cs[CS_NUMBER]; /* used to store cs info in time gamma */
struct inf_info ht[HT_NUMBER]; /* used to store ht info in time gamma */
struct inf_info ht_tmp[HT_NUMBER];
static double inf_start_timestamp;
static double delay_start_timestamp;
static double inf_end_timestamp;    /* we record time to ouput the result */
static int pi = 0; /*use as the start point of neighbor packet_info */
static int pj = 0;

static int start_pointer = 0;
static int end_pointer = 0;

static pcap_t* pcap_handle = NULL;
pcap_dumper_t *pkt;
FILE *fin2;
static unsigned int rear = 0 ;
static unsigned int front = 0;
/*GLOBAL VALUE*/
struct packet_info p;
struct neighbor * nb;
static int nb_num = 1;

void init_neighbor(struct neighbor* n)
{
	int i =0;
	for(i = 0 ; i < HOLD_TIME ; i++)
		n->pkt_all_data[i] = 0;
	n->pkt_all = 0;
	n->pkt_all_retry = 0;
	n->cli = NULL;
	n->next = NULL;
}
const char*
ether_sprintf(const unsigned char *mac)
{
	static char etherbuf[13];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf;
}

const char*
ether_sprintf2(const unsigned char *mac)
{
	static char etherbuf2[13];
	snprintf(etherbuf2, sizeof(etherbuf2), "%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf2;
}



int parse_tcp_header(const unsigned char *buf, struct packet_info* p,int left_len)
{
	/* data */
	struct tcphdr* th;
//	if (len > 0 && (size_t)len < sizeof(struct tcphdr))
//		return -1;
	th = (struct tcphdr*)buf;
	p->tcp_seq = ntohl(th->seq);
	p->tcp_ack = ntohl(th->ack_seq);
	int tcplen = 4*th->doff; /*tcp header len*/
	double time_pch1 = (double)((double)p->tv.tv_sec + (double)((double)p->tv.tv_usec/1000000.0));
	if ( (th->ack == 0) && (th->syn == 1) )
	{
		p->tcp_type = TCP_SYN;
		p->tcp_next_seq = p->tcp_seq + 1;
	}
	else if ( (th->ack == 1) && (th->syn == 1) )
	{
		p->tcp_type = TCP_SYN_ACK;
		p->tcp_next_seq = p->tcp_seq + 1;
	}
	else if ( (th->ack == 0) && (th->fin == 1)  )
	{
		p->tcp_type = TCP_FIN_ACK;
		p->tcp_next_seq = p->tcp_seq + 1;
	}
	else if ( (th->ack == 1) && (th->fin == 0) && (th->syn == 0))
	{
		if(left_len == tcplen)
		{
			p->tcp_type = TCP_ACK;
			p->tcp_next_seq = p->tcp_seq + 1;
		}
		else
		{
			p->tcp_type = TCP_DATA;
			p->tcp_next_seq = p->tcp_seq + left_len - tcplen;		
		}
	}
	else
	{
		p->tcp_type = TCP_OTHER;
	}
	printf("%lf,seq=%u,ack=%u,nex_seq=%u,",time_pch1,p->tcp_seq,p->tcp_ack,p->tcp_next_seq);
	printf("tcplen=%d,left_len=%d",tcplen,left_len);
	switch(p->tcp_type)
	{
		case TCP_ACK:
			printf("TCP_ACK\n");
			break;
		case TCP_DATA:
			printf("TCP_DATA\n");
			break;
		case TCP_SYN:
			printf("TCP_SYN\n");
			break;
		case TCP_FIN_ACK:
			printf("TCP_FIN_ACK\n");
			break;
		case TCP_SYN_ACK:
			printf("TCP_SYN_ACK\n");
			break;
		case TCP_OTHER:
			printf("TCP_OTHER\n");
			break;
		default:
			break;
	}
	
	return 0;
}
/* return 1 if we parsed enough = min ieee header */
int parse_wire_packet(const unsigned char *buf,  struct packet_info* p)
{
	
	

	u8 *raw = (u8 *)(buf+14);
	if(((*raw) & 0x60) == 0x40){
		struct ip* ih;
		ih = (struct ip*)(buf+14);
		int ipl = ih->ip_hl*4;
		
		p->tcp_offset = 14 + ipl;
		int left_len = p->len - 14 - ipl;
		if (ih && ih->ip_p && (ih->ip_p  == IPPROTO_TCP))
			parse_tcp_header(buf+p->tcp_offset,p,left_len);
	}else{
		p->tcp_offset = 14 + IPV6; //ipv6
		/*need to be continue...*/
	}

	return 0;
}
			  

const char*
digest_sprintf16(const unsigned char *mac)   
{
	static char etherbuf[33];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],mac[6]
		,mac[7], mac[8], mac[9], mac[10], mac[11], mac[12],mac[13]
		,mac[14], mac[15]);
	return etherbuf;
}
const char*
digest_sprintf30(const unsigned char *mac)   
{
	static char etherbuf[61];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],mac[6]
		,mac[7], mac[8], mac[9], mac[10], mac[11], mac[12],mac[13]
		,mac[14], mac[15], mac[16], mac[17], mac[18], mac[19]
		,mac[20], mac[21], mac[22], mac[23], mac[24], mac[25]
		,mac[26], mac[27], mac[28], mac[29]);
	return etherbuf;
}

int str_equal(const unsigned char *s1,const unsigned char *s2,int len){
	int i ;
	for (i = 0; i < len ; i++)
	{
		if(( s1[i] != s2[i] )&&(tolower(s1[i]) != s2[i]))
			return 0;
	}
	return 1;
}

void reset_one_line(int j)
{

	int no = 0;
	struct neighbor *tmp = nb;
	while (no < nb_num)
	{
		tmp->pkt_all_data[j] = 0;
		tmp = tmp->next;
		no = no + 1;
	}
	hold[j] = 0;

}


static int print_delay(struct delay_info* delay, int index)
{
	/*note: we discard the delay using syn-ack and fin-ack*/
	if( (store[index].tcp_type == TCP_ACK ) && (str_equal(mac,ether_sprintf(p.wlan_dst),2*MAC_LEN) == 1) )
	{
		int i ;
		for(i = 1;i <5; i++)
		{
			if(store[index-i].tcp_next_seq == store[index].tcp_ack)
			{
				double tw_data = store[index-i].tv.tv_sec + (double)store[index-i].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
				double tr_ack = store[index].tv.tv_sec + (double)store[index].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
				delay->time1 = tw_data;
				delay->time2 = tr_ack;
				delay->tcp_seq = store[index-i].tcp_seq;
				memcpy(delay->wlan_src,ether_sprintf(store[index-i].wlan_src),MAC_LEN);
				memcpy(delay->wlan_dst,ether_sprintf2(store[index-i].wlan_dst),MAC_LEN);
				break;
			}
		}
		return C2AP_ACK;
	}
	else if( (store[index].tcp_type == TCP_ACK) && (str_equal(mac,ether_sprintf(p.wlan_src),2*MAC_LEN) == 1) )
	{
		int i ;
		for(i = 1;i <5; i++)
		{
			if(store[index-i].tcp_next_seq == store[index].tcp_ack)
			{
				double tw_data = store[index-i].tv.tv_sec + (double)store[index-i].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
				double tw_ack = store[index].tv.tv_sec + (double)store[index].tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
				delay->time1 = tw_data;
				delay->time2 = tw_ack;
				delay->tcp_seq = store[index-i].tcp_seq;
				memcpy(delay->wlan_src,ether_sprintf(store[index-i].wlan_src),MAC_LEN);
				memcpy(delay->wlan_dst,ether_sprintf2(store[index-i].wlan_dst),MAC_LEN);
				break;
			}
		}
		return AP2C_ACK;
	}
	else
	{
		/*do nothing*/
		return 0;
	}
}


/**************************************/
static int write_frequent_update_delay() {
  //printf("Writing frequent log to %s\n", PENDING_FREQUENT_UPDATE_FILENAME);
  FILE* handle = fopen(PENDING_FREQUENT_UPDATE_FILENAME_DELAY_WIRE, "w");
printf("in the write_frequent_update_delay file!\n"); 
  if (!handle) {
    perror("Could not open update file for writing\n");
    exit(1);
  }
 	int rounds =(rpp - start_pointer + HOLD_TIME )%HOLD_TIME;
 	int i = 0;
 	int ii = start_pointer;
 	printf("from %d to %d, rounds is %d\n",start_pointer,rpp,rounds);
 	while(i < rounds )
 	{
		
 		struct delay_info delay;
 		int direction = print_delay(&delay,ii);
		//printf("direction is:%d,ii is :%d",direction,ii);
 		switch(direction)
 		{
 			case C2AP_ACK:
 				fprintf(handle,"%lf,%lf,%s,%s,%u\n",delay.time1,delay.time2,ether_sprintf(delay.wlan_src),ether_sprintf2(p.wlan_dst),delay.tcp_seq);
				break;
 			case AP2C_ACK:
 				fprintf(handle,"%lf,%lf,%s,%s,%u\n",delay.time1,delay.time2,ether_sprintf(delay.wlan_src),ether_sprintf2(p.wlan_dst),delay.tcp_seq);
				break;
 			default:
 			/*do nothing*/
				break;
 		}
 		i = (i+1);
 		ii = (ii+1)%HOLD_TIME;
 	}
 /***************************/
	if(debug == 1)
		printf("unlock and fileclose is good!\n");
/*****************************/
  char update_filename[FILENAME_MAX];
  snprintf(update_filename,
           FILENAME_MAX,
           FREQUENT_UPDATE_FILENAME,
           mac,
           mac,
           1,
           frequent_sequence_number);
  if (rename(PENDING_FREQUENT_UPDATE_FILENAME_DELAY_WIRE, update_filename)) {
    perror("Could not stage update");
    exit(1);
  }
  
 /************************/
	if(debug == 1)
		printf("rename is good!\n");
/*************************/

  start_timestamp_microseconds
      = nb->start_timeval.tv_sec + nb->start_timeval.tv_usec/NUM_MICROS_PER_SECOND;
  ++frequent_sequence_number;

    struct pcap_stat statistics;
    pcap_stats(pcap_handle, &statistics);

	if (debug == 11)
	{
		printf("received is: %d,dropped is: %d, total packets are :%d\n",statistics.ps_recv,statistics.ps_drop,rpp);
	}
	start_pointer = rpp;
}


/**************************************/


/* libpcap calls this function for every packet it receives. */
static void process_packet(
        u_char* const user,
        const struct pcap_pkthdr* const header,
        const u_char* const bytes) {
 // if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
  //  perror("sigprocmask");
 //   exit(1);
 // }

//	int i = 0;
	float busywait = 0;
  ++rp;


	memset(&p, 0, sizeof(p));
	p.len = header->len;
	p.tv.tv_sec = header->ts.tv_sec;
	p.tv.tv_usec = header->ts.tv_usec;
	rpp++;
	parse_wire_packet(bytes,&p);
	

	/*begin store packet*/
	memcpy(store[rpp%HOLD_TIME].tcp_header,bytes+p.tcp_offset,16);
	memcpy(store[rpp%HOLD_TIME].wlan_src,p.wlan_src,MAC_LEN);
	memcpy(store[rpp%HOLD_TIME].wlan_dst,p.wlan_dst,MAC_LEN);
	store[rpp%HOLD_TIME].tv.tv_sec = p.tv.tv_sec;
	store[rpp%HOLD_TIME].tv.tv_usec = p.tv.tv_usec;
	store[rpp%HOLD_TIME].len = p.len;
	store[rpp%HOLD_TIME].wlan_type = p.wlan_type;
	store[rpp%HOLD_TIME].wlan_retry = p.wlan_retry;
	store[rpp%HOLD_TIME].phy_signal = p.phy_signal;
	store[rpp%HOLD_TIME].phy_rate = p.phy_rate;
	store[rpp%HOLD_TIME].timestamp = p.timestamp;
	store[rpp%HOLD_TIME].tcp_seq = p.tcp_seq;
	store[rpp%HOLD_TIME].tcp_next_seq = p.tcp_next_seq;
	
	pj = rpp%HOLD_TIME;
	end_pointer = rpp%HOLD_TIME;
	if(debug == 1)
	{
		double neighbor_timestamp = (double)p.timestamp/(double)NUM_NANO_PER_SECOND;	
		double libpcap_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;
	
		printf("+++++packet %d:%f<---->%f\n",rpp,neighbor_timestamp,libpcap_timestamp);	
	}
	/*end store packet*/


	inf_end_timestamp = p.tv.tv_sec + (double)p.tv.tv_usec/(double)NUM_MICROS_PER_SECOND;

	if ((inf_end_timestamp - delay_start_timestamp) > FREQUENT_UPDATE_DELAY_SECONDS)
	{
		/*print out*/
		printf("begin print...\n");
		write_frequent_update_delay(); /*write the delay into the file*/
		delay_start_timestamp = inf_end_timestamp;
	}

	if(debug == 10) //just for debug count
	{
		if((pch_count_debug % every) == 0)
		{
			printf("wireless data packet and loss is:[%d] and [%d]\n",rpp,pch_count_debug);	
		}
	}
	if(debug == 3)
		pcap_dump(user,header,bytes);
	//}//for 136
  
 

  //if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
   // perror("sigprocmask");
   // exit(1);
  //}
 
}




 static pcap_t* initialize_pcap(const char* const interface) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* const handle = pcap_open_live(
      interface, BUFSIZ, PCAP_PROMISCUOUS, PCAP_TIMEOUT_MILLISECONDS, errbuf);
  if (!handle) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    return NULL;
  }

    fprintf(stderr, "type is %d\n",pcap_datalink(handle));

  return handle;
}

static void clear_station(struct neighbor* p,int j)
{
	p->pkt_all_data[j] = 0;
}



static void set_next_alarm() {
  alarm(FREQUENT_UPDATE_PERIOD_SECONDS);
}

/* Unix only provides a single ALRM signal, so we use the same handler for
 * frequent updates (every 5 seconds) and differential updates (every 30
 * seconds). We trigger an ALRM every 5 seconds and only write differential
 * updates every 6th ALRM. */
static void handle_signals(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    exit(0);
  } else if (sig == SIGALRM) {
    write_frequent_update();
    set_next_alarm();
  }
}

static void initialize_signal_handler(){
	struct sigaction action;
	action.sa_handler = handle_signals;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;
	if (sigaction(SIGINT, &action, NULL) < 0
		|| sigaction(SIGTERM, &action, NULL) < 0
		|| sigaction(SIGALRM, &action, NULL)) {
		perror("sigaction");
		exit(1);
	}
	sigemptyset(&block_set);
	sigaddset(&block_set, SIGINT);
	sigaddset(&block_set, SIGTERM);
	sigaddset(&block_set, SIGALRM);
}
int main(int argc,char *argv[]){

	
    if (argc < 5) {
    fprintf(stderr, "Usage: %s <interface> <debug> <write-interval> <mac> <every>\n", argv[0]);
    }
	
	printf("hello world\n");
	printf("%s\n",argv[1]);
	debug = atoi(argv[2]);
	FREQUENT_UPDATE_PERIOD_SECONDS = atoi(argv[3]);
	memcpy(mac,argv[4],12);
	printf("%s\n",mac);
	every = atoi(argv[5]);
	FREQUENT_UPDATE_DELAY_SECONDS = every;
 //fin2=fopen(argv[2],"a+");

	//if(fin2==NULL)
	//{
	//	printf("File Open Error!\n");	
	//	exit(1);
	//}
	
	
	

	
	//initialize_signal_handler();
	//set_next_alarm();
	
	
	
	pcap_handle = initialize_pcap(argv[1]);
	
	if(!pcap_handle){
		return 1;
	}
	
	pkt = pcap_dump_open(pcap_handle,DUMP_DIR);
	
	nb = (struct neighbor *)malloc(sizeof(struct neighbor));
	init_neighbor(nb);
	pcap_loop(pcap_handle,QUEUE_SIZE,process_packet,(u_char *)pkt);
	
	
	printf("end capturing......\n");
	
	//fclose(fin2);
	
	return 0;
}
