/* 			pcap for pd 0.0.5 (renamed pdpcap)                                  */
/*		Jordi Sala poperbu@gmail.com 20101011                 		            */
/*										                                        */
/* --------------------------  pcap for pd------------------------------------- */
/*                                                                              */
/* Is an External Objects for pd that uses lipcap to capture/read pcap files    */
/* and analizing network traffic packets                                        */
/* network packets=> Network Sniffer                              		        */
/* sources and more info: http://musa.poperbu.net/puredata 	          	        */
/*                                                                              */
/* This program is free software; you can redistribute it and/or                */
/* modify it under the terms of the GNU General Public License                  */
/* as published by the Free Software Foundation; either version 2               */
/* of the License, or (at your option) any later version.                       */
/*                                                                              */
/* This program is distributed in the hope that it will be useful,              */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of               */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                */
/* GNU General Public License for more details.                                 */
/*                                                                              */
/* You should have received a copy of the GNU General Public License            */
/* along with this program; if not, write to the Free Software                  */
/* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  */
/* ---------------------------------------------------------------------------- */
#define __USE_BSD
#define _BSD_SOURCE

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ctype.h>
#include <netdb.h>

#include "m_pd.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

EXTERN_STRUCT pcap_pkthdr;
#define t_header struct pcap_pkthdr

#define MAXFILTERARGS 10
#define MAXFILTERLENG MAXPDSTRING

//static t_class *pcappd_class;

typedef struct _pcap_pd {

    t_outlet *x_outlet2;        /*packet number*/
    t_outlet *x_outlet3;        /*Ethernet info*/
    t_outlet *x_outlet4;        /*IP protocol*/
    t_outlet *x_outlet5;        /*src IP address*/
    t_outlet *x_outlet6;        /*dst IP address*/
    t_outlet *x_outlet7;        /*src_port number*/
    t_outlet *x_outlet8;        /*dst_port number*/
    t_outlet *x_outlet9;        /*packet header*/
    t_outlet *x_outlet10;       /*data in hexa*/

    //capture options
    int x_debug;
    int x_payloadon;            /*show on/off payload*/
    int x_num_packets;          /* number of packets to capture */
    int x_limited_capture;
    int x_previus_np;
    int x_timeout;              /*timeou for pcap functions*/
    int x_delay;                /*delay for loop mode*/
    size_t x_maxdata;                 /*number of bytes to print of data part*/
    t_float x_loop;             /*loop mode on/off inlet2*/
    int x_write_file;           /*pcap save file*/
    int x_running;

    //counters
    int x_ok_cap;                /*total packets processed*/
    int x_count;                /*total packets processed*/
    int x_lastcount;
    int x_num_packets_count;    /*current packets processed*/
    int x_ip_count;             /*ip packets processed*/
    int x_tcp_count;            /*tcp packets processed*/
    int x_udp_count;            /*udp packets processed*/
    int x_icmp_count;           /*icmp packets processed*/
    int x_unk_count;            /*unknown packets processed*/
    int x_unkip_count;            /*unknown ip packets processed*/
    int x_arp_count;            /*arp packets processed*/
    int x_rarp_count;           /*rarp packets processed*/


    //libpcap
    bpf_u_int32     x_mask;			    /* subnet mask */
    bpf_u_int32     x_net;			    /* net address */
    bpf_u_int32     x_ip4;              /*ip address*/
    char            x_errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
    struct bpf_program x_fp;		    /* compiled filter program (expression) */
    pcap_t          *x_handle;	        /* packet capture handle */
    const u_char    *x_packet;          /*captured packet*/
    struct pcap_pkthdr *x_header;       /*packet header*/
    char            *x_filter_exp;      /* filter expression [3] */
    char            x_errbuf2[PCAP_ERRBUF_SIZE+256];	/* error buffer2 */
    char            *x_wfilename;      //pcap source file name to write
    pcap_dumper_t   *x_dumpfile;        //pcap source file to write

    //packet handle
    struct ip    *x_ip;
    const u_char    *x_payload;


    //from ether header
    char    x_src_mac[20];
    char    x_dst_mac[20];
    char    x_ethtype[20];
    int     x_nethtype;

    //from ip header
    char    x_src_ip[20];
    char    x_dest_ip[20];
    char    x_protoname[20];
    int     x_ip_len;
    size_t  x_data_len;

    //from protocol header (tcp, udp icmp)
    t_float x_sport;
    t_float x_dport;


} t_pcap_pd;

void pcap_got_packet(t_pcap_pd *x);
void pcap_ether_packet(t_pcap_pd *x);
void pcap_ip_packet(t_pcap_pd *x);
void pcap_tcp_packet(t_pcap_pd *x);
void pcap_udp_packet(t_pcap_pd *x);
void pcap_icmp_packet(t_pcap_pd *x);
void pcap_packet_out(t_pcap_pd *x);
void pcap_out_payload(t_pcap_pd *x);
void pcap_print_payload(t_pcap_pd *x);
void pcap_hex_ascii_line(t_pcap_pd *x, const u_char *payload, int len, int offset);
void pcap_filter_set(t_pcap_pd *x, t_symbol *s, int argc, t_atom *argv);
void pcap_dumping_file(t_pcap_pd *x);


//PACKET PROCESSING
//pocess the packet captured by pcap.
void pcap_got_packet(t_pcap_pd *x)
{

    x->x_count++;
    x->x_num_packets_count++;

    t_float f = x->x_count;
    outlet_float(x->x_outlet2, f);

    //if dump is on, traffic is saved in pcap file
    if (x->x_write_file == 1){
         pcap_dump(x->x_dumpfile,x->x_header,x->x_packet);
    }

	if (x->x_header->caplen != x->x_header->len) {
		error("pcap: %d != %d!!! Don't have complete packet. Skipping.\n",
			x->x_header->caplen, x->x_header->len);
		return;
	}
    //process packet->only ethernet packets.
    //pcap_device_ether_packet(x);
    pcap_ether_packet(x);

    //IS IP PACKET:
    if (ntohs(x->x_nethtype) == ETHERTYPE_IP) {

        //pcap_device_ip_packet(x);
        pcap_ip_packet(x);

        switch (x->x_ip->ip_p) {

            case IPPROTO_ICMP:
                    pcap_icmp_packet(x);
                    break;

            case IPPROTO_TCP:
                    pcap_tcp_packet(x);
                    break;

            case IPPROTO_UDP:
                    pcap_udp_packet(x);
                    break;

            default:
                outlet_symbol(x->x_outlet4, gensym("UNKNOWN"));
                outlet_float(x->x_outlet7, 0);
                outlet_float(x->x_outlet8, 0);
                x->x_unkip_count=x->x_unkip_count++;
                sprintf(x->x_protoname,"unknown");
        }
        pcap_packet_out(x);
        x->x_ok_cap=1;
        return;
    }
    else{
        //NO IP PACKET
        pcap_packet_out(x);
        x->x_ok_cap=1;
        return;
    }

}


//ETHERNET
void pcap_ether_packet(t_pcap_pd *x)
{
    struct ether_header *ether;
    ether = (struct ether_header *) x->x_packet;
    char ether_info[60];

    x->x_nethtype=ether->ether_type;

    switch (ntohs(x->x_nethtype)) {
        case ETHERTYPE_IP:
            sprintf(x->x_ethtype,"IP");
            break;

        case ETHERTYPE_ARP:
            sprintf(x->x_ethtype,"ARP");
            x->x_arp_count=x->x_arp_count++;
            break;

        case ETHERTYPE_REVARP:
            sprintf(x->x_ethtype,"RARP");
            x->x_rarp_count=x->x_rarp_count++;
            break;

        default:
            sprintf(x->x_ethtype,"unknown");
            x->x_unk_count=x->x_unk_count++;
    }

    sprintf(x->x_src_mac,"%s",ether_ntoa((struct ether_addr*)ether->ether_shost));
    sprintf(x->x_dst_mac,"%s",ether_ntoa((struct ether_addr*)ether->ether_dhost));

    sprintf(ether_info,"Type: %s MAC:%s dMac:%s",x->x_ethtype,x->x_src_mac,x->x_dst_mac);

   outlet_symbol(x->x_outlet3,gensym(ether_info));

    return;
}

//IP
void pcap_ip_packet(t_pcap_pd *x)
{
        size_t datalen2;
        t_float ln;
        x->x_ip_count=x->x_ip_count++;
        x->x_ip = (struct ip *) (x->x_packet + sizeof(struct ether_header) );

        x->x_ip_len = ntohs(x->x_ip->ip_len) - sizeof(struct ip);

        ln =x->x_ip_len;

        datalen2 = x->x_ip_len - x->x_ip->ip_len * 4;
        /*if data size is bigger than max data*/
        if (datalen2 >= (x->x_maxdata)){
            x->x_data_len=x->x_maxdata;
        }else{
            x->x_data_len=datalen2;
        }
        /* Get source and destination addresses */
        strcpy(x->x_src_ip, inet_ntoa( *(struct in_addr *) &x->x_ip->ip_src) );
        strcpy(x->x_dest_ip, inet_ntoa( *(struct in_addr *) &x->x_ip->ip_dst) );

        outlet_symbol(x->x_outlet5, gensym(x->x_src_ip));
        outlet_symbol(x->x_outlet6, gensym(x->x_dest_ip));
        sprintf(x->x_ethtype,"IP");

    return;
}

//TCP packet analizing
void pcap_tcp_packet(t_pcap_pd *x)
{
    struct tcphdr   *tcp;
    int size_tcp = sizeof(struct tcphdr);

    sprintf(x->x_protoname,"TCP");
    outlet_symbol(x->x_outlet4, gensym("TCP"));

    tcp = (struct tcphdr *) ( (char *) x->x_ip + sizeof(struct ip) );
    //x->x_sport = ntohs(tcp->source);
    x->x_sport = ntohs(tcp->th_sport);

    outlet_float(x->x_outlet7, x->x_sport);
    //x->x_dport = ntohs(tcp->dest);
    x->x_dport = ntohs(tcp->th_dport);

    outlet_float(x->x_outlet8, x->x_dport);
    x->x_tcp_count=x->x_tcp_count++;

    //PAYLOAD
    if (x->x_payloadon == 1){
        x->x_payload=(u_char *)tcp+size_tcp;
        pcap_out_payload(x);
    }
    return;
}

//UDP packet analizing
void pcap_udp_packet(t_pcap_pd *x)
{
    struct udphdr *udp;

    int size_udp=sizeof(struct udphdr);
    sprintf(x->x_protoname,"UDP");

    outlet_symbol(x->x_outlet4, gensym("UDP"));

    udp = (struct udphdr *) ( (char *) x->x_ip + sizeof(struct ip) );
    //x->x_sport = ntohs(udp->source);
    x->x_sport = ntohs(udp->uh_sport);

    outlet_float(x->x_outlet7, x->x_sport);
    //x->x_dport = ntohs(udp->dest);
    x->x_dport = ntohs(udp->uh_dport);

    outlet_float(x->x_outlet8, x->x_dport);
    x->x_udp_count=x->x_udp_count++;

    if (x->x_payloadon == 1){
        x->x_payload=(u_char *)udp+size_udp;
        pcap_out_payload(x);
    }
    return;
}

//ICMP packets
void pcap_icmp_packet(t_pcap_pd *x)
{
    struct icmp  *icmp;
    x->x_sport=0;
    x->x_dport=0;
    int size_icmp = sizeof(struct icmp);
    sprintf(x->x_protoname,"ICMP");

    icmp = (struct icmp *) ( (char *) x->x_ip + sizeof(struct icmp) );

    outlet_symbol(x->x_outlet4, gensym("ICMP"));

    outlet_float(x->x_outlet7, x->x_sport);

    outlet_float(x->x_outlet8, x->x_dport);
    x->x_icmp_count=x->x_icmp_count++;

    //PAYLOAD
    if (x->x_payloadon == 1){
        x->x_payload=(u_char *)icmp+size_icmp;
        pcap_out_payload(x);
    }
    return;
}

//show packet in outlet9 / and prints in console in debug mode.
void pcap_packet_out(t_pcap_pd *x){

    char header_out[MAXPDSTRING];

    //header output
    sprintf(header_out,"%d ethtype IP version %d smac %s dmac %s len %d srcip %s dstip %s ttl %d proto %d chcks %d TOS %d id %d offset %d sport %d dport %d",
                x->x_count,(x->x_ip->ip_v),x->x_src_mac,x->x_dst_mac,(x->x_ip->ip_len),x->x_src_ip,x->x_dest_ip,(x->x_ip->ip_ttl),(x->x_ip->ip_p),
                (int)(x->x_ip->ip_sum),(int)(x->x_ip->ip_tos),(int)(x->x_ip->ip_id),(int)(x->x_ip->ip_off),(int)x->x_sport,(int)x->x_dport);
    outlet_symbol(x->x_outlet9,gensym(header_out));

    //DEBUG

    if (x->x_debug){
        post("=============================PACKET %d======================================", x->x_count);
        post("EthernetType: %s",x->x_ethtype);
        post("Src.MacAddress:%s",x->x_src_mac);
        post("Dst.MacAddress:%s",x->x_dst_mac);

        if (ntohs(x->x_nethtype) == ETHERTYPE_IP){
            post("IP Packet Length: %d bytes - IP data Length: %d bytes", x->x_ip->ip_len, x->x_ip_len);
            post("Src.IPAdress:%s", x->x_src_ip);
            post("Dst.IPAdress:%s",x->x_dest_ip);
            post("\tttl: %d\tProt.:%d \tChks.: %d \tTOS: %d",(x->x_ip->ip_ttl),(x->x_ip->ip_p),(x->x_ip->ip_sum),(x->x_ip->ip_tos));
            post("\tId: %d\tFrgOffset: %d",(x->x_ip->ip_id),(x->x_ip->ip_off));

            post("IP protocol: %s",x->x_protoname);
            post("Source port: %d, Destination port %d",(int)x->x_sport, (int)x->x_dport);
            if (x->x_payloadon == 1){
                pcap_print_payload(x);
            }
        }
        post("=============================================================================");
    }
    return;

}


//outputs packet data to outlet10 in HEX.
void pcap_out_payload(t_pcap_pd *x)
{
    int i;
    int len;
    len = x->x_data_len;
	const u_char *ch = x->x_payload;
    char *hexline;
    //char *asciiline;
    char *buf;
    //char *buf2;

    hexline=(char *)getbytes(MAXPDSTRING* len * sizeof(char));
    //asciiline=(char *)getbytes(MAXPDSTRING *len * sizeof(char));

    buf=(char *)getbytes(MAXPDSTRING* len * sizeof(char));
    //buf2=(char *)getbytes(MAXPDSTRING* len * sizeof(char));

    char *buffer[MAXPDSTRING*len];
    //char *buffer2[MAXPDSTRING*len];

	if (len <= 0)
		return;

	for(i=0;i<len;i++){
        sprintf(buf,"%02x ", *ch);
        //sprintf(buf2,"%c", *ch);
        buffer[i]=buf;
        //buffer2[i]=buf2;
        strcat(hexline,buffer[i]);
        //strcat(asciiline,buffer2[i]);
        ch++;
    }
    //outlet_symbol(x->x_outlet10, gensym(asciiline));
    outlet_symbol(x->x_outlet10, gensym(hexline));
    return;
}

//Print data in console when debug is ON
void pcap_print_payload(t_pcap_pd *x)
{
    int len;
    len = x->x_data_len;
	int len_rem = len;
	int line_width = 16;
	int line_len;
	int offset = 0;
	const u_char *ch = x->x_payload;
    post("----------------------------------------------------------------------------");

	if (len <= 0)
		return;
	/* data fits on one line */
	if (len <= line_width) {
		pcap_hex_ascii_line(x,ch, len, offset);
		return;
	}
	/* data spans multiple lines */
	for ( ;; ) {
		line_len = line_width % len_rem;
		pcap_hex_ascii_line(x,ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			pcap_hex_ascii_line(x,ch, len_rem, offset);
			break;
		}
	}
return;
}

//Print line in console when debug is ON
void pcap_hex_ascii_line(t_pcap_pd *x, const u_char *payload, int len, int offset)
{
    int i;
	const u_char *ch;
    char *outline;
    char *hexline;
    char *hexline2;
    char *ascline;
    char *buf;
    char *buf2;
    char *buffer[32*len];
    char *buffer2[32*len];
    hexline=(char *)getbytes(32 *len * sizeof(char));
    hexline2=(char *)getbytes(32 * len * sizeof(char));
    outline=(char *)getbytes(32 * len * sizeof(char));
    ascline=(char *)getbytes(32 *len * sizeof(char));
    buf=(char *)getbytes(len * sizeof(char));
    buf2=(char *)getbytes(len * sizeof(char));

    sprintf(outline,"%05d",offset);

	ch = payload;
	for(i = 0; i < len; i++) {
		sprintf(buf,"%02x ", *ch);
        buffer[i]=buf;
        strcat(hexline,buffer[i]);
        if (isprint(*ch)){
			sprintf(buf2,"%c", *ch);
            buffer2[i]=buf2;
		}else{
			buffer2[i]=".";
		}
		strcat(ascline,buffer2[i]);
        ch++;
    }
    post("%d %s: %s %s : %s",x->x_count,outline, hexline,hexline2,ascline);

    return;
}

//packet filter setting
void pcap_filter_set(t_pcap_pd *x, t_symbol *s, int argc, t_atom *argv)
{
    typedef char cstring[MAXFILTERLENG];
    int i;
    cstring*buf=(cstring*)getbytes(MAXFILTERARGS*sizeof(cstring));
    cstring buffer;
    for(i=0; i<MAXFILTERARGS; i++)*buf[i]=0;
    for (i=0; i<argc; i++) {
		atom_string(argv+i, buf[i], MAXFILTERLENG);
        if (i<(argc-1)){
            strcat(buf[i]," ");
        }
	}
    sprintf(x->x_filter_exp,"%s%s%s%s%s%s%s%s%s%s",buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]);
    freebytes(buf, MAXFILTERARGS*sizeof(cstring));
	s=gensym(buffer);
	post("pcap: New pcap Filter %s.", x->x_filter_exp);

}

//OPEN DUMP FILE TO SAVE CAPTURED PACKETS
void pcap_dumping_file(t_pcap_pd *x){
    if (x->x_write_file ==1){
        if(!x->x_handle){
            post("pcap: No handle opened, can't open dumpfile.");
            x->x_write_file=0;
        }else{
            x->x_dumpfile=pcap_dump_open(x->x_handle, x->x_wfilename);
            if(x->x_dumpfile==NULL){
                post("pcap: Error opening output dump file %s.",x->x_wfilename);
                x->x_write_file=0;
            }else{
                post("pcap: Dumping data to %s.", x->x_wfilename);
            }
        }
    }
}
