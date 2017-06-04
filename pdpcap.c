/*DEPRECATED		->use pcap for pd objects: pcap_device pcap_file            */
/* 			pdpcap.c 0.0.4 	                                                    */
/*		Jordi Sala poperbu@gmail.com 20100929                 		            */
/*										                                        */
/* --------------------------  pdpcap     ------------------------------------- */
/*                                                                              */
/* Is an External Object for pd that uses lipcap to capture and analizing	    */
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


static t_class *pdpcap_class;

typedef struct _pdpcap {
    t_object  x_obj;
    t_outlet *x_outlet1;        /*connection status*/
    t_outlet *x_outlet2;        /*packet number*/
    t_outlet *x_outlet3;        /*Ethernet info*/
    t_outlet *x_outlet4;        /*IP protocol*/
    t_outlet *x_outlet5;        /*src IP address*/
    t_outlet *x_outlet6;        /*dst IP address*/
    t_outlet *x_outlet7;        /*src_port number*/
    t_outlet *x_outlet8;        /*dst_port number*/
    t_outlet *x_outlet9;        /*packet header*/
    t_outlet *x_outlet10;       /*data in hexa*/
    t_outlet *b_out;            /*end of capture bang*/
    t_clock *x_clock;

    //capture options
    int x_debug;
    int x_payloadon;            /*show on/off payload*/
    int x_num_packets;          /* number of packets to capture */
    int x_limited_capture;
    int x_previus_np;
    int x_connected;            /*pcap connected */
    int x_timeout;              /*timeou for pcap functions*/
    int x_delay;                /*delay for loop mode*/
    size_t x_maxdata;                 /*number of bytes to print of data part*/
    t_float x_loop;             /*loop mode on/off inlet2*/
    int x_default_dev;           /*default or custom device*/
    int x_num_of_devs;          /*number of devices*/
    int x_reading_file;         /*pcap reading file*/
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


    //pcap
    bpf_u_int32     x_mask;			    /* subnet mask */
    bpf_u_int32     x_net;			    /* net address */
    bpf_u_int32     x_ip4;              /*ip address*/
    char            x_errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
    struct bpf_program x_fp;		    /* compiled filter program (expression) */
    pcap_t          *x_handle;	        /* packet capture handle */
    char            *x_dev;		        /* capture device name */
    const u_char    *x_packet;          /*captured packet*/
    struct pcap_pkthdr *x_header;       /*packet header*/
    char            *x_filter_exp;      /* filter expression [3] */
    pcap_if_t       *x_all_devs;         /*list of all devices*/
    char            x_errbuf2[PCAP_ERRBUF_SIZE+256];	/* error buffer2 */
    char            *x_rfilename;      //pcap source file to read
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

    //info
    int         x_host_ok;
    char        x_host_ip[20];
    char        x_host_net[20];
    char        x_host_mask[20];
    char        x_host_name[32];
    char        *x_default_devname;           /*default device*/


    //from protocol header (tcp, udp icmp)
    t_float x_sport;
    t_float x_dport;
} t_pdpcap;


void pdpcap_tick(t_pdpcap *x);
void pdpcap_got_packet(t_pdpcap *x);
void pdpcap_out_payload(t_pdpcap *x);
void pdpcap_print_payload(t_pdpcap *x);
void pdpcap_hex_ascii_line(t_pdpcap *x, const u_char *payload, int len, int offset);
void pdpcap_ether_packet(t_pdpcap *x);
void pdpcap_ip_packet(t_pdpcap *x);
void pdpcap_tcp_packet(t_pdpcap *x);
void pdpcap_udp_packet(t_pdpcap *x);
void pdpcap_icmp_packet(t_pdpcap *x);
void pdpcap_packet_out(t_pdpcap *x);
void pdpcap_device_net_info(t_pdpcap *x);
void pdpcap_device_ipaddr4(t_pdpcap *x);
void pdpcap_file_dump(t_pdpcap *x);



//PCAP CONNECT TO DEVICE
void pdpcap_connect(t_pdpcap *x)
{
    t_float c;
    if(x->x_reading_file == 1){
        post("pdpcap: pdpcap is reading a file..");
    }else{
        if (x->x_num_packets == 0){x->x_num_packets=1;}
        if (x->x_default_dev==0){
            post("pdpcap: Looking for default device..");
            x->x_dev = pcap_lookupdev(x->x_errbuf);
        }
        if (x->x_dev == NULL) {
            error("pdpcap: Couldn't find device.%s", x->x_dev);
        }
        else{
             post("pdpcap: Selected/Detected Device: %s", x->x_dev);
            /* get network number and maskmask associated with capture device */
            if (pcap_lookupnet(x->x_dev, &x->x_net, &x->x_mask, x->x_errbuf) == -1) {
                error("pdpcap: Couldn't get netmask for device %s: %s",x->x_dev, x->x_errbuf);
                x->x_net= 0;
                x->x_mask = 0;
                x->x_connected=0;
            }
            else{
                /* print capture info */
                 post("pdpcap: Device: %s", x->x_dev);
                 if (x->x_debug)post("pdpcap: Number of packets: %d", x->x_num_packets);
                 if (x->x_debug)post("pdpcap: Filter expression: %s", x->x_filter_exp);
                /* open capture device */
                //x->x_handle = pcap_open_live(x->x_dev, SNAP_LEN, 1, 1000, x->x_errbuf);
                x->x_handle = pcap_open_live(x->x_dev, SNAP_LEN, 1, x->x_timeout, x->x_errbuf);
                if (x->x_handle == NULL) {
                    error("pdpcap: Couldn't open device %s: %s", x->x_dev, x->x_errbuf);
                    x->x_connected=0;
                }
                else{
                     post("pdpcap: device %s: %s opened", x->x_dev, x->x_errbuf);
                    /* make sure we're capturing on an Ethernet device [2] */
                    /*if (pcap_setnonblock(x->x_handle, 1, x->x_errbuf) == -1) {
                        post("pdpcap: Failed to set NonBlocking mode.");
                    }else{
                        post("pdpcap: NonBlcocking mode.");
                    }*/
                    if (pcap_datalink(x->x_handle) != DLT_EN10MB) {
                        error("pdpcap: %s is not an Ethernet", x->x_dev);
                        x->x_connected=0;
                    }
                    else{
                        post("pdpcap: %s is an Ethernet->ok", x->x_dev);
                        /* compile the filter expression */
                        if (pcap_compile(x->x_handle, &x->x_fp, x->x_filter_exp, 0, x->x_net ) == -1) {
                            error("pdpcap: Couldn't parse filter %s: %s", x->x_filter_exp, pcap_geterr(x->x_handle));
                            x->x_connected=0;
                        }
                        else{
                            post("pdpcap: Filter Parsed %s: %s -> Ok", x->x_filter_exp, pcap_geterr(x->x_handle));
                            /* apply the compiled filter */
                            if (pcap_setfilter(x->x_handle, &x->x_fp) == -1) {
                                error("pdpcap: Couldn't install filter %s: %s", x->x_filter_exp, pcap_geterr(x->x_handle));
                                x->x_connected=0;
                            }
                            else{
                                post("pdpcap: Filter Installed  %s: %s-> Ok", x->x_filter_exp, pcap_geterr(x->x_handle));
                                x->x_connected=1;
                                pdpcap_file_dump(x);
                            }
                        }
                    }
                }
            }
        }
        c=x->x_connected;
        outlet_float(x->x_outlet1,c);
    }
}

//PCAP FILE READ
void pdpcap_file_read(t_pdpcap *x, t_symbol *s, int argc, t_atom *argv)
{
    t_float c;
    int ok;
    int next_res;
    next_res=0;
    ok=0;
    if (x->x_connected==1){
        post("pdpcap: pdpca is connected, can't open file now.");
    }else{
        if (x->x_reading_file == 1){
            post("pdpcap: A file is already opened.");
        }else{
            if (x->x_num_packets == 0){x->x_num_packets=1;}
            if(argc == 1){
                s=atom_getsymbol(argv);
                x->x_rfilename=s->s_name;
                post("pdpcap: Filename %s selected.", x->x_rfilename);
                //x->x_reading_file=1;
                x->x_handle=pcap_open_offline(x->x_rfilename, x->x_errbuf);
                if(!x->x_handle){
                    error("pdpcap: Error opening %s file.",x->x_rfilename);
                    x->x_reading_file=0;
                }else{
                    post("pdpcap: Analizing %s file....",x->x_rfilename);
                    /* compile the filter expression */
                    if (pcap_compile(x->x_handle, &x->x_fp, x->x_filter_exp, 0, x->x_net ) == -1) {
                        error("pdpcap: Couldn't parse filter %s: %s", x->x_filter_exp, pcap_geterr(x->x_handle));
                        x->x_reading_file=0;
                    }else{
                        post("pdpcap: Filter Parsed %s: %s -> Ok", x->x_filter_exp, pcap_geterr(x->x_handle));
                        /* apply the compiled filter */
                        if (pcap_setfilter(x->x_handle, &x->x_fp) == -1) {
                            error("pdpcap: Couldn't install filter %s: %s", x->x_filter_exp, pcap_geterr(x->x_handle));
                            x->x_reading_file=0;
                        }else{
                            post("pdpcap: Filter Installed  %s: %s-> Ok", x->x_filter_exp, pcap_geterr(x->x_handle));
                            x->x_reading_file=1;
                            pdpcap_file_dump(x);
                        }
                    }
                }
            }else{
                post("pdpcap: No file name.");
                x->x_reading_file=0;
            }
        }
        c=x->x_reading_file;
        outlet_float(x->x_outlet1,c);
    }
    return;
}

//DISCONNECT DEVICE OR CLOSE PCAP FILE
void pdpcap_disconnect(t_pdpcap *x){
    t_float c;
    int conn;
    conn=0;
    if (x->x_connected == 0){
        post("pdpcap: device was not connected NOT connected.");
        if (x->x_reading_file == 1){
            pcap_close(x->x_handle);
            x->x_reading_file=0;
            c=x->x_reading_file;
            outlet_float(x->x_outlet1,c);
            post("pdpcap: Ok file %s closed.",x->x_rfilename);
            conn=1;
        }else{
            post("pdpcap: No file opened.");
        }
    }else{
        post("pdpcap: OK device %s disconnected.", x->x_dev);
        pcap_freecode(&x->x_fp);
        pcap_close(x->x_handle);
        //pcap_freealldevs(x->x_all_devs);
        x->x_connected=0;
        c=x->x_connected;
        outlet_float(x->x_outlet1,c);
        conn=1;
    }
    //close dump file if it is open.
    if (conn == 1){
        if (x->x_write_file==1){
            post("pdpcap: Ok dumpfile %s closed.",x->x_wfilename);
            pcap_dump_close(x->x_dumpfile);
            x->x_write_file=0;
        }
    }
    x->x_running=0;
}

//CAPTURE TRAFFIC FROM DEVICE (OF FROM READ FILE)
void pdpcap_capture(t_pdpcap *x){
    int ok;
    int next_res;
    //next_res=0;
    next_res=-1;
    ok=0;
    x->x_ok_cap=0;
    //x->x_num_packets_count=0;
    x->x_running=1;
    struct pcap_pkthdr *header;
    header=x->x_header;
    if (x->x_connected == 0 && x->x_reading_file == 0){
        error("pdpcap: NOT connected or not reading file.");
        x->x_running=0;
    }else{
        if (x->x_loop==0){
            if(x->x_num_packets_count < x->x_num_packets){
                if (x->x_debug)post("pdpcap: capturing %d of %d packets", x->x_num_packets_count, x->x_num_packets);
                if (x->x_num_packets_count==1)x->x_limited_capture=1;
                ok=1;
            }else{
                if (x->x_num_packets_count==1){
                    x->x_limited_capture=1;
                    ok=0;
                }else{
                    ok=0;
                }
            }
        }else{
            ok=1;
            if (x->x_num_packets_count==1)
            {
                x->x_previus_np=x->x_num_packets;
                x->x_num_packets=1;
                x->x_limited_capture=0;
            }
        }
        if (ok==1){

            next_res=pcap_next_ex(x->x_handle, &x->x_header, &x->x_packet);

            if (next_res == 0){
                if (x->x_debug)post("pdpcap: waiting for paquets...");
            }
            if (next_res == 1){
                x->x_lastcount=x->x_count;
                pdpcap_got_packet(x);
                outlet_bang(x->b_out);
            }
            if(next_res==-1){
                error("pdpcap: ERROR %s",x->x_errbuf);
            }
            clock_delay(x->x_clock,x->x_delay);
            pcap_freecode(&x->x_fp);

        }else{

            post("pdpcap: Capture finished");
            post("pdpcap:TOTAL num pkt processed: %d", x->x_count);
            post("pdpcap:   IP: %d (tcp: %d udp: %d icmp: %d others: %d)",
                    x->x_ip_count,x->x_tcp_count,x->x_udp_count,x->x_icmp_count,x->x_unkip_count);
            post("pdpcap:   ARP: %d", x->x_arp_count);
            post("pdpcap:   RARP: %d", x->x_rarp_count);
            post("pdpcap:   OTHERS: %d", x->x_unk_count);
            x->x_num_packets_count=0;
            //x->x_running=0;
            if (x->x_limited_capture==0){
              x->x_num_packets=x->x_previus_np;
            }
        }
    }
    return;
}

//SET NAME FOR DUMP FILE AND SET DUMP ON.
void pdpcap_file_dump_name(t_pdpcap *x, t_symbol *s, int argc, t_atom *argv)
{
    if (x->x_running==1){
        post("pdpcap: Running, try again later");
    }else{
        if(argc == 1){
            s=atom_getsymbol(argv);
            x->x_wfilename=s->s_name;
            post("pdpcap: Filename to dump %s.", x->x_wfilename);
            x->x_write_file=1;
        }else{
            post("pdpcap: No filename to dump.");
            x->x_write_file=0;
            x->x_wfilename=NULL;
        }
    }
   // return;
}

//OPEN DUMP FILE TO SAVE CAPTURED PACKETS
void pdpcap_file_dump(t_pdpcap *x){
    if (x->x_write_file ==1){
        if(!x->x_handle){
            post("pdpcap: No handle opened, can't open dumpfile.");
            x->x_write_file=0;
        }else{
            x->x_dumpfile=pcap_dump_open(x->x_handle, x->x_wfilename);
            if(x->x_dumpfile==NULL){
                post("pdpcap: Error opening output file %s.",x->x_wfilename);
                x->x_write_file=0;
            }else{
                post("pdpcap: Dumping data to %s.", x->x_wfilename);
            }
        }
    }
}

//PACKET PROCESSING
//pocess the packet captured by pcap.
void pdpcap_got_packet(t_pdpcap *x)
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
		error("pdpcap: %d != %d!!! Don't have complete packet. Skipping.\n",
			x->x_header->caplen, x->x_header->len);
		return;
	}
    //process packet->only ethernet packets.
    pdpcap_ether_packet(x);

    //IS IP PACKET:
    if (ntohs(x->x_nethtype) == ETHERTYPE_IP) {

        pdpcap_ip_packet(x);

        switch (x->x_ip->ip_p) {

            case IPPROTO_ICMP:
                    pdpcap_icmp_packet(x);
                    break;

            case IPPROTO_TCP:
                    pdpcap_tcp_packet(x);
                    break;

            case IPPROTO_UDP:
                    pdpcap_udp_packet(x);
                    break;

            default:
                outlet_symbol(x->x_outlet4, gensym("UNKNOWN"));
                outlet_float(x->x_outlet7, 0);
                outlet_float(x->x_outlet8, 0);
                x->x_unkip_count=x->x_unkip_count++;
                sprintf(x->x_protoname,"unknown");
        }
        pdpcap_packet_out(x);
        x->x_ok_cap=1;
        return;
    }
    else{
        //NO IP PACKET
        pdpcap_packet_out(x);
        x->x_ok_cap=1;
        return;
    }

}

//outputs packet data to outlet10.
void pdpcap_ether_packet(t_pdpcap *x)
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


//IP PACKET
void pdpcap_ip_packet(t_pdpcap *x)
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

//show packet in outlet9 / and prints in console in debug mode.
void pdpcap_packet_out(t_pdpcap *x){

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
                pdpcap_print_payload(x);
            }
        }
        post("=============================================================================");
    }
    return;

}

//TCP packet analizing
void pdpcap_tcp_packet(t_pdpcap *x)
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
        pdpcap_out_payload(x);
    }
    return;
}

//UDP packet analizing
void pdpcap_udp_packet(t_pdpcap *x)
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
        pdpcap_out_payload(x);
    }
    return;
}

//ICMP packets
void pdpcap_icmp_packet(t_pdpcap *x)
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
        pdpcap_out_payload(x);
    }
    return;
}

//outputs packet data to outlet10 in HEX.
void pdpcap_out_payload(t_pdpcap *x)
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
void pdpcap_print_payload(t_pdpcap *x)
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
		pdpcap_hex_ascii_line(x,ch, len, offset);
		return;
	}
	/* data spans multiple lines */
	for ( ;; ) {
		line_len = line_width % len_rem;
		pdpcap_hex_ascii_line(x,ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			pdpcap_hex_ascii_line(x,ch, len_rem, offset);
			break;
		}
	}
return;
}

//Print line in console when debug is ON
void pdpcap_hex_ascii_line(t_pdpcap *x, const u_char *payload, int len, int offset)
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



//INLETS
void pdpcap_numpackets_set(t_pdpcap *x, t_floatarg f)
{
    x->x_num_packets=f;
    post("pdpcap: Number of packets:%d",x->x_num_packets);
}

//set loop (continous) capture mode
void pdpcap_loop_set(t_pdpcap *x, t_floatarg f)
{
    x->x_loop=f;
    x->x_num_packets=1;
    post("pdpcap: Loop set to:%d",x->x_loop);
    post("pdpcap: Number of packets (by default in loop mode):%d",x->x_num_packets);
}

//sets timout
void pdpcap_timeout_set(t_pdpcap *x, t_floatarg f)
{
    x->x_timeout=f;
    post("pdpcap: Timeout set to:%d",x->x_timeout);
}

//packet filter setting
void pdpcap_filter_set(t_pdpcap *x, t_symbol *s, int argc, t_atom *argv)
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
	post("pdpcap: New pcap Filter %s.", x->x_filter_exp);

}

//time delay
void pdpcap_delay_loop_set(t_pdpcap *x, t_floatarg f)
{
    x->x_delay=f;
    post("pdpcap: Delay set to:%d",x->x_delay);
}

//set data to output
void pdpcap_data_set(t_pdpcap *x, t_floatarg f)
{
    if (f > 0){
        x->x_maxdata=f;
        x->x_payloadon=1;
        post("pdpcap: Data out ON");
        post("pdpcap: Max bytes output set to:%d",x->x_maxdata);
    }else{
        x->x_maxdata=0;
        x->x_payloadon=0;
        post("pdpcap: Data out OFF");
    }

}

//sets debug mode
void pdpcap_debug_set(t_pdpcap *x, t_floatarg f)
{
    if (f==0 || f==1){
        x->x_debug=f;
        post("pdpcap: Debug set to:%d",x->x_debug);
    }
    else{
        error("pdpcap: Wrong value for debug (0 or 1)");
    }
}

//prints pdpcap info
void pdpcap_info(t_pdpcap *x)
{
    post("pdpcap: PDPCAP INFO:");
    post("pdpcap: Number of devices: %d", x->x_num_of_devs);
    post("pdpcap: Device %s selected.", x->x_dev);
    post("pdpcap: connected: %d", x->x_connected);
    post("pdpcap: debug: %d", x->x_debug);
    post("pdpcap: num_packets to capture: %d", x->x_num_packets);
    post("pdpcap: timeout: %d", x->x_timeout);
    post("pdpcap: delay: %d", x->x_delay);
    post("pdpcap:TOTAL num pkt processed: %d", x->x_count);
    post("pdpcap:   IP: %d (tcp: %d udp: %d icmp: %d others: %d)",
        x->x_ip_count,x->x_tcp_count,x->x_udp_count,x->x_icmp_count,x->x_unkip_count);
    post("pdpcap:   ARP: %d", x->x_arp_count);
    post("pdpcap:   RARP: %d", x->x_rarp_count);
    post("pdpcap:   OTHERS: %d", x->x_unk_count);

}
//select device to capture by number id
void pdpcap_device_num(t_pdpcap *x, t_floatarg f)
{
        int num = 0;
        pcap_if_t* d;
        x->x_default_dev=0;
        for(d=x->x_all_devs; d; d=d->next) {
            if(num==f){
                x->x_dev=d->name;
                post("pdpcap: Device %d: %s selected.", num, x->x_dev);
                x->x_default_dev=1;
            }
            num++;
        }

        if (x->x_default_dev==0){
                error("pdpcap: Device %d doesn't exist.",num);
                //post("pdpcap: No device selected");
                x->x_dev=NULL;
        }
        pdpcap_device_net_info(x);
}
void pdpcap_tick(t_pdpcap *x)
{
  pdpcap_capture(x);
}


//reset to default settings
void pdpcap_reset(t_pdpcap *x)
{
    x->x_num_packets=1;
    x->x_num_packets_count=0;
    x->x_debug=0;
    x->x_connected=0;
    x->x_reading_file=0;
    x->x_write_file=0;
    x->x_count=0;
    x->x_timeout=500;
    x->x_delay=100;
    if (x->x_default_dev==1){
        x->x_dev=x->x_default_devname;
    }else{
        pdpcap_device_num(x,0);
    }
    x->x_ip_count=0;
    x->x_tcp_count=0;
    x->x_udp_count=0;
    x->x_icmp_count=0;
    x->x_unkip_count=0;
    x->x_unk_count=0;
    x->x_arp_count=0;
    x->x_rarp_count=0;
    x->x_maxdata=0;
    x->x_num_of_devs=0;

    pdpcap_info(x);
}

//DEVICE INFO
void pdpcap_device_select(t_pdpcap *x, t_symbol *s, int argc, t_atom *argv)
{

    if(argc == 1){
        s=atom_getsymbol(argv);
        x->x_dev=s->s_name;
        post("pdpcap: Device %s selected.", x->x_dev);
        x->x_default_dev=1;
        pdpcap_device_net_info(x);
        //one ping timeout 2 sec
    }else{
        post("pdpcap: No device selected. Selecting device 0..");
        pdpcap_device_num(x,0);
        //x->x_dev=NULL;
        //x->x_default_dev=0;
    }

}

//look for all computer devices
void pdpcap_device_find(t_pdpcap *x){
       // Retrieve the system network device list
    if (pcap_findalldevs(&x->x_all_devs, x->x_errbuf2) == -1) {
        error("pdpcap: pcap_findalldevs\n");
        return;
    }
    if (x->x_all_devs) {
        // Count how many devices are discovered
        int num = 0;
        pcap_if_t* d;
        post("pdpcap: LIST of system DEVICES:");
        for(d=x->x_all_devs; d; d=d->next) {
            post("pdpcap:       %d: %s", num, d->name);
            num++;
        }
        x->x_num_of_devs=num;
        post("pdpcap: Total number of devices: %d",x->x_num_of_devs);

    }else {
        post("pdpcap: No network interface detected.");
        post("pdpcap: Make sure you have enough rights.");
        return;
    }
}
//show selected device basic info
void pdpcap_device_info(t_pdpcap *x)
{
    if (x->x_dev == NULL) {
        post("pdpcap: No device selected.");
    }else{
        pdpcap_device_net_info(x);
        //
        post("pdpcap: DEVICE INFO:");
        post("pdpcap:       Name: %s",x->x_dev);
        post("pdpcap:       IPv4 Address %s", x->x_host_ip);
        post("pdpcap:       Network Address: %s", x->x_host_net);
        post("pdpcap:       Netmask: %s", x->x_host_mask);
    }
}

//looks for selected device network information
void pdpcap_device_net_info(t_pdpcap *x)
{
    bpf_u_int32     dmask;			    /* subnet mask */
    bpf_u_int32     dip;			    /* net addr */
    struct in_addr tmp,tmp2;

    if (x->x_default_dev==0){
        post("pdpcap: No device selected. Selecting device 0..");
        pdpcap_device_num(x,0);
    }

    //get ipv4 addr for device
    pdpcap_device_ipaddr4(x);

    if (pcap_lookupnet(x->x_dev, &dip, &dmask, x->x_errbuf) == -1) {
        error("pdpcap: Couldn't get info for device %s: %s",x->x_dev, x->x_errbuf);
    }
    else{
        x->x_net=dip;
        x->x_mask=dmask;
        tmp.s_addr=dip;
        tmp2.s_addr=dmask;
        sprintf(x->x_host_net, "%s", inet_ntoa(tmp));
        sprintf(x->x_host_mask, "%s", inet_ntoa(tmp2));
    }
}

//looks for selected device ip address
void pdpcap_device_ipaddr4(t_pdpcap *x)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, x->x_dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    sprintf(x->x_host_ip, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

//looks for selected device hostname
void pdpcap_host_name(t_pdpcap *x){
    if (gethostname(x->x_host_name, 32)==-1){
        error("pdpcap: Can't get hostname.");
    }
}


void *pdpcap_new(t_symbol *s)
{
    t_pdpcap *x = (t_pdpcap *)pd_new(pdpcap_class);
    floatinlet_new(&x->x_obj, &x->x_loop);
    x->x_outlet1 = outlet_new(&x->x_obj, &s_float);	            /*connection status */
    x->x_outlet2 = outlet_new(&x->x_obj, &s_float);             /*packet number*/
    x->x_outlet3 = outlet_new(&x->x_obj, &s_float);             /*Ethernet Info*/
    x->x_outlet4 = outlet_new(&x->x_obj, &s_symbol);            /*IP protocol*/
    x->x_outlet5 = outlet_new(&x->x_obj, &s_symbol);            /*source IP address*/
    x->x_outlet6 = outlet_new(&x->x_obj, &s_symbol);            /*dest IP address*/
    x->x_outlet7 = outlet_new(&x->x_obj, &s_float);             /*src_port number*/
    x->x_outlet8 = outlet_new(&x->x_obj, &s_float);             /*dst_port number*/
    x->x_outlet9 = outlet_new(&x->x_obj, &s_float);             /*packet header*/
    x->x_outlet10 = outlet_new(&x->x_obj, &s_symbol);           /*payload*/

    x->b_out = outlet_new(&x->x_obj, &s_bang);                /*end of capture bang*/

    x->x_clock = clock_new(x, (t_method)pdpcap_tick);

    x->x_filter_exp = (char *)getbytes(MAXFILTERLENG * sizeof(char));

    x->x_num_packets=1;
    x->x_num_packets_count=0;
    x->x_debug=0;
    x->x_connected=0;
    x->x_reading_file=0;
    x->x_write_file=0;
    x->x_count=0;
    x->x_timeout=500;
    x->x_delay=100;
    x->x_ip_count=0;
    x->x_tcp_count=0;
    x->x_udp_count=0;
    x->x_icmp_count=0;
    x->x_unk_count=0;
    x->x_maxdata=0;
    x->x_default_dev=0;
    x->x_num_of_devs=0;
    x->x_running=0;
    t_symbol *devicesel;
    devicesel=s;
    x->x_dev=s->s_name;
    if (s->s_name[0]){
        x->x_dev=devicesel->s_name;
        x->x_default_devname=devicesel->s_name;
        x->x_default_dev=1;
    }else{
        x->x_dev=NULL;
    }
    pdpcap_device_find(x);
    post("pdpcap: Device %s selected.",x->x_dev);
    pdpcap_device_net_info(x);
    return (void *)x;
}

void pdpcap_setup(void) {
    pdpcap_class = class_new(gensym("pdpcap"), (t_newmethod)pdpcap_new, 0,
        sizeof(t_pdpcap),0,A_DEFSYMBOL, 0);

    class_addmethod(pdpcap_class,
        (t_method)pdpcap_connect, gensym("connect"),0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_disconnect, gensym("disconnect"),0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_capture, gensym("capture"),0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_numpackets_set, gensym("packets"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_timeout_set, gensym("timeout"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_delay_loop_set, gensym("delay"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_debug_set, gensym("debug"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_reset, gensym("reset"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_info, gensym("info"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_filter_set, gensym("filter"),
        A_GIMME,0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_data_set, gensym("data"),
        A_DEFFLOAT,0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_device_select, gensym("device"),
        A_GIMME,0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_device_find, gensym("device_list"),0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_device_num, gensym("device_num"),
        A_DEFFLOAT, 0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_device_info, gensym("device_info"),0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_file_read, gensym("file_read"),
        A_GIMME,0);
    class_addmethod(pdpcap_class,
        (t_method)pdpcap_file_dump_name, gensym("file_dump"),
        A_GIMME,0);
}
