/* 		PCAP for PD 0.0.5: pcap_device.c  	                                    */
/*		Jordi Sala poperbu@gmail.com 20100929                 		            */
/*										                                        */
/* --------------------------  pcap_device------------------------------------- */
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

#include "pcap.h"


static t_class *pcap_device_class;

typedef struct _pcap_device {
    t_object  x_obj;
    t_outlet *x_outlet1;        /*connection status*/
    //t_outlet *x_outlet2;        /*packet number*/
    //t_outlet *x_outlet3;        /*Ethernet info*/
    //t_outlet *x_outlet4;        /*IP protocol*/
    //t_outlet *x_outlet5;        /*src IP address*/
    //t_outlet *x_outlet6;        /*dst IP address*/
    //t_outlet *x_outlet7;        /*src_port number*/
    //t_outlet *x_outlet8;        /*dst_port number*/
    //t_outlet *x_outlet9;        /*packet header*/
    //t_outlet *x_outlet10;       /*data in hexa*/
    t_outlet *b_out;            /*end of capture bang*/
    t_clock *x_clock;

    t_pcap_pd x_pcap_pd;

    int         x_connected;            /*pcap connected */
    int         x_default_dev;          /*default or custom device*/
    int         x_num_of_devs;          /*number of devices*/
    char        *x_dev;		            /* capture device name */
    pcap_if_t   *x_all_devs;            /*list of all devices*/
    char        *x_default_devname;           /*default device*/

    //info
    int         x_host_ok;
    char        x_host_ip[20];
    char        x_host_net[20];
    char        x_host_mask[20];
    char        x_host_name[32];



} t_pcap_device;


void pcap_device_tick(t_pcap_device *x);
void pcap_device_net_info(t_pcap_device *x);
void pcap_device_ipaddr4(t_pcap_device *x);



//PCAP CONNECT TO DEVICE
void pcap_device_connect(t_pcap_device *x)
{
    t_float c;

        if (x->x_pcap_pd.x_num_packets == 0){x->x_pcap_pd.x_num_packets=1;}
        if (x->x_default_dev==0){
            post("pcap: Looking for default device..");
            x->x_dev = pcap_lookupdev(x->x_pcap_pd.x_errbuf);
        }
        if (x->x_dev == NULL) {
            error("pcap: Couldn't find device.%s", x->x_dev);
        }
        else{
             post("pcap: Selected/Detected Device: %s", x->x_dev);
            /* get network number and maskmask associated with capture device */
            if (pcap_lookupnet(x->x_dev, &x->x_pcap_pd.x_net, &x->x_pcap_pd.x_mask, x->x_pcap_pd.x_errbuf) == -1) {
                error("pcap: Couldn't get netmask for device %s: %s",x->x_dev, x->x_pcap_pd.x_errbuf);
                x->x_pcap_pd.x_net= 0;
                x->x_pcap_pd.x_mask = 0;
                x->x_connected=0;
            }
            else{
                /* print capture info */
                 post("pcap: Device: %s", x->x_dev);
                 if ((x->x_pcap_pd.x_debug)==1)post("pcap: Number of packets: %d", x->x_pcap_pd.x_num_packets);
                 if (x->x_pcap_pd.x_debug==1)post("pcap: Filter expression: %s", x->x_pcap_pd.x_filter_exp);
                /* open capture device */
                //x->x_pcap_pd.x_handle = pcap_open_live(x->x_dev, SNAP_LEN, 1, 1000, x->x_pcap_pd.x_errbuf);
                x->x_pcap_pd.x_handle = pcap_open_live(x->x_dev, SNAP_LEN, 1, x->x_pcap_pd.x_timeout, x->x_pcap_pd.x_errbuf);
                if (x->x_pcap_pd.x_handle == NULL) {
                    error("pcap: Couldn't open device %s: %s", x->x_dev, x->x_pcap_pd.x_errbuf);
                    x->x_connected=0;
                }
                else{
                     post("pcap: device %s: %s opened", x->x_dev, x->x_pcap_pd.x_errbuf);
                    /* make sure we're capturing on an Ethernet device [2] */
                    /*if (pcap_setnonblock(x->x_pcap_pd.x_handle, 1, x->x_pcap_pd.x_errbuf) == -1) {
                        post("pcap: Failed to set NonBlocking mode.");
                    }else{
                        post("pcap: NonBlcocking mode.");
                    }*/
                    if (pcap_datalink(x->x_pcap_pd.x_handle) != DLT_EN10MB) {
                        error("pcap: %s is not an Ethernet", x->x_dev);
                        x->x_connected=0;
                    }
                    else{
                        post("pcap: %s is an Ethernet->ok", x->x_dev);
                        /* compile the filter expression */
                        if (pcap_compile(x->x_pcap_pd.x_handle, &x->x_pcap_pd.x_fp, x->x_pcap_pd.x_filter_exp, 0, x->x_pcap_pd.x_net ) == -1) {
                            error("pcap: Couldn't parse filter %s: %s", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                            x->x_connected=0;
                        }
                        else{
                            post("pcap: Filter Parsed %s: %s -> Ok", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                            /* apply the compiled filter */
                            if (pcap_setfilter(x->x_pcap_pd.x_handle, &x->x_pcap_pd.x_fp) == -1) {
                                error("pcap: Couldn't install filter %s: %s", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                                x->x_connected=0;
                            }
                            else{
                                post("pcap: Filter Installed  %s: %s-> Ok", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                                x->x_connected=1;
                                pcap_dumping_file(&x->x_pcap_pd);
                            }
                        }
                    }
                }
            }
        }
        c=x->x_connected;
        outlet_float(x->x_outlet1,c);
}


//DISCONNECT DEVICE OR CLOSE PCAP FILE
void pcap_device_disconnect(t_pcap_device *x){
    t_float c;
    int conn;
    conn=0;
    if (x->x_connected == 0){
        post("pcap: device was not connected NOT connected.");
    }else{
        post("pcap: OK device %s disconnected.", x->x_dev);
        pcap_freecode(&x->x_pcap_pd.x_fp);
        pcap_close(x->x_pcap_pd.x_handle);
        //pcap_freealldevs(x->x_all_devs);
        x->x_connected=0;
        c=x->x_connected;
        outlet_float(x->x_outlet1,c);
        conn=1;
    }
    //close dump file if it is open.
    if (conn == 1){
        if (x->x_pcap_pd.x_write_file==1){
            post("pcap: Ok dumpfile %s closed.",x->x_pcap_pd.x_wfilename);
            pcap_dump_close(x->x_pcap_pd.x_dumpfile);
            x->x_pcap_pd.x_write_file=0;
        }
    }
    x->x_pcap_pd.x_running=0;
}

//CAPTURE TRAFFIC FROM DEVICE (OF FROM READ FILE)
void pcap_device_capture(t_pcap_device *x){
    int ok;
    int next_res;
    //next_res=0;
    next_res=-1;
    ok=0;
    x->x_pcap_pd.x_ok_cap=0;
    //x->x_pcap_pd.x_num_packets_count=0;
    x->x_pcap_pd.x_running=1;
    struct pcap_pkthdr *header;
    header=x->x_pcap_pd.x_header;
    if (x->x_connected == 0){
        error("pcap: NOT connected.");
        x->x_pcap_pd.x_running=0;
    }else{
        if (x->x_pcap_pd.x_loop==0){
            if(x->x_pcap_pd.x_num_packets_count < x->x_pcap_pd.x_num_packets){
                if (x->x_pcap_pd.x_debug)post("pcap: capturing %d of %d packets", x->x_pcap_pd.x_num_packets_count, x->x_pcap_pd.x_num_packets);
                if (x->x_pcap_pd.x_num_packets_count==1)x->x_pcap_pd.x_limited_capture=1;
                ok=1;
            }else{
                if (x->x_pcap_pd.x_num_packets_count==1){
                    x->x_pcap_pd.x_limited_capture=1;
                    ok=0;
                }else{
                    ok=0;
                }
            }
        }else{
            ok=1;
            if (x->x_pcap_pd.x_num_packets_count==1)
            {
                x->x_pcap_pd.x_previus_np=x->x_pcap_pd.x_num_packets;
                x->x_pcap_pd.x_num_packets=1;
                x->x_pcap_pd.x_limited_capture=0;
            }
        }
        if (ok==1){

            next_res=pcap_next_ex(x->x_pcap_pd.x_handle, &x->x_pcap_pd.x_header, &x->x_pcap_pd.x_packet);

            if (next_res == 0){
                if (x->x_pcap_pd.x_debug)post("pcap: waiting for paquets...");
            }
            if (next_res == 1){
                x->x_pcap_pd.x_lastcount=x->x_pcap_pd.x_count;
                pcap_got_packet(&x->x_pcap_pd);
                outlet_bang(x->b_out);
            }
            if(next_res==-1){
                error("pcap: ERROR %s",x->x_pcap_pd.x_errbuf);
            }
            clock_delay(x->x_clock,x->x_pcap_pd.x_delay);
            pcap_freecode(&x->x_pcap_pd.x_fp);

        }else{

            post("pcap: Capture finished");
            post("pcap:TOTAL num pkt processed: %d", x->x_pcap_pd.x_count);
            post("pcap:   IP: %d (tcp: %d udp: %d icmp: %d others: %d)",
                    x->x_pcap_pd.x_ip_count,x->x_pcap_pd.x_tcp_count,x->x_pcap_pd.x_udp_count,x->x_pcap_pd.x_icmp_count,x->x_pcap_pd.x_unkip_count);
            post("pcap:   ARP: %d", x->x_pcap_pd.x_arp_count);
            post("pcap:   RARP: %d", x->x_pcap_pd.x_rarp_count);
            post("pcap:   OTHERS: %d", x->x_pcap_pd.x_unk_count);
            x->x_pcap_pd.x_num_packets_count=0;
            //x->x_pcap_pd.x_running=0;
            if (x->x_pcap_pd.x_limited_capture==0){
              x->x_pcap_pd.x_num_packets=x->x_pcap_pd.x_previus_np;
            }
        }
    }
    return;
}

//SET NAME FOR DUMP FILE AND SET DUMP ON.
void pcap_device_file_dump_name(t_pcap_device *x, t_symbol *s, int argc, t_atom *argv)
{
    if (x->x_pcap_pd.x_running==1){
        post("pcap: Running, try again later");
    }else{
        if(argc == 1){
            s=atom_getsymbol(argv);
            x->x_pcap_pd.x_wfilename=s->s_name;
            post("pcap: Filename to dump %s.", x->x_pcap_pd.x_wfilename);
            x->x_pcap_pd.x_write_file=1;
        }else{
            post("pcap: No filename to dump.");
            x->x_pcap_pd.x_write_file=0;
            x->x_pcap_pd.x_wfilename=NULL;
        }
    }
   // return;
}

//INLETS
void pcap_device_numpackets_set(t_pcap_device *x, t_floatarg f)
{
    x->x_pcap_pd.x_num_packets=f;
    post("pcap: Number of packets:%d",x->x_pcap_pd.x_num_packets);
}

//set loop (continous) capture mode
void pcap_device_loop_set(t_pcap_device *x, t_floatarg f)
{
    x->x_pcap_pd.x_loop=f;
    x->x_pcap_pd.x_num_packets=1;
    post("pcap: Loop set to:%d",x->x_pcap_pd.x_loop);
    post("pcap: Number of packets (by default in loop mode):%d",x->x_pcap_pd.x_num_packets);
}

//sets timout
void pcap_device_timeout_set(t_pcap_device *x, t_floatarg f)
{
    x->x_pcap_pd.x_timeout=f;
    post("pcap: Timeout set to:%d",x->x_pcap_pd.x_timeout);
}

//packet filter setting
void pcap_device_filter_set(t_pcap_device *x, t_symbol *s, int argc, t_atom *argv)
{
    pcap_filter_set(&x->x_pcap_pd,s,argc,argv);
    if (x->x_connected == 1){
        post("pcap: Re-connect device to apply new filter.");
    }
}

//time delay
void pcap_device_delay_loop_set(t_pcap_device *x, t_floatarg f)
{
    x->x_pcap_pd.x_delay=f;
    post("pcap: Delay set to:%d",x->x_pcap_pd.x_delay);
}

//set data to output
void pcap_device_data_set(t_pcap_device *x, t_floatarg f)
{
    if (f > 0){
        x->x_pcap_pd.x_maxdata=f;
        x->x_pcap_pd.x_payloadon=1;
        post("pcap: Data out ON");
        post("pcap: Max bytes output set to:%d",x->x_pcap_pd.x_maxdata);
    }else{
        x->x_pcap_pd.x_maxdata=0;
        x->x_pcap_pd.x_payloadon=0;
        post("pcap: Data out OFF");
    }

}

//sets debug mode
void pcap_device_debug_set(t_pcap_device *x, t_floatarg f)
{
    if (f==0 || f==1){
        x->x_pcap_pd.x_debug=f;
        post("pcap: Debug set to:%d",x->x_pcap_pd.x_debug);
    }
    else{
        error("pcap: Wrong value for debug (0 or 1)");
    }
}

//select device to capture by number id
void pcap_device_num(t_pcap_device *x, t_floatarg f)
{
        int num = 0;
        pcap_if_t* d;
        x->x_default_dev=0;
        for(d=x->x_all_devs; d; d=d->next) {
            if(num==f){
                x->x_dev=d->name;
                post("pcap: Device %d: %s selected.", num, x->x_dev);
                x->x_default_dev=1;
            }
            num++;
        }

        if (x->x_default_dev==0){
                error("pcap: Device %d doesn't exist.",num);
                //post("pcap: No device selected");
                x->x_dev=NULL;
        }
        pcap_device_net_info(x);
}
//prints pcap_device info
void pcap_device_info(t_pcap_device *x)
{
    post("pcap: PDPCAP INFO:");
    post("pcap: Number of devices: %d", x->x_num_of_devs);
    post("pcap: Device %s selected.", x->x_dev);
    post("pcap: connected: %d", x->x_connected);
    post("pcap: debug: %d", x->x_pcap_pd.x_debug);
    post("pcap: num_packets to capture: %d", x->x_pcap_pd.x_num_packets);
    post("pcap: timeout: %d", x->x_pcap_pd.x_timeout);
    post("pcap: delay: %d", x->x_pcap_pd.x_delay);
    post("pcap:TOTAL num pkt processed: %d", x->x_pcap_pd.x_count);
    post("pcap:   IP: %d (tcp: %d udp: %d icmp: %d others: %d)",
        x->x_pcap_pd.x_ip_count,x->x_pcap_pd.x_tcp_count,x->x_pcap_pd.x_udp_count,x->x_pcap_pd.x_icmp_count,x->x_pcap_pd.x_unkip_count);
    post("pcap:   ARP: %d", x->x_pcap_pd.x_arp_count);
    post("pcap:   RARP: %d", x->x_pcap_pd.x_rarp_count);
    post("pcap:   OTHERS: %d", x->x_pcap_pd.x_unk_count);

}

void pcap_device_tick(t_pcap_device *x)
{
pcap_device_capture(x);
}


//reset to default settings
void pcap_device_reset(t_pcap_device *x)
{
    x->x_pcap_pd.x_num_packets=1;
    x->x_pcap_pd.x_num_packets_count=0;
    x->x_pcap_pd.x_debug=0;
    x->x_connected=0;
    x->x_pcap_pd.x_write_file=0;
    x->x_pcap_pd.x_count=0;
    x->x_pcap_pd.x_timeout=500;
    x->x_pcap_pd.x_delay=100;
    if (x->x_default_dev==1){
        x->x_dev=x->x_default_devname;
    }else{
        pcap_device_num(x,0);
    }
    x->x_pcap_pd.x_ip_count=0;
    x->x_pcap_pd.x_tcp_count=0;
    x->x_pcap_pd.x_udp_count=0;
    x->x_pcap_pd.x_icmp_count=0;
    x->x_pcap_pd.x_unkip_count=0;
    x->x_pcap_pd.x_unk_count=0;
    x->x_pcap_pd.x_arp_count=0;
    x->x_pcap_pd.x_rarp_count=0;
    x->x_pcap_pd.x_maxdata=0;
    x->x_num_of_devs=0;

    pcap_device_info(x);
}

//DEVICE INFO
void pcap_device_select(t_pcap_device *x, t_symbol *s, int argc, t_atom *argv)
{

    if(argc == 1){
        s=atom_getsymbol(argv);
        x->x_dev=s->s_name;
        post("pcap: Device %s selected.", x->x_dev);
        x->x_default_dev=1;
        pcap_device_net_info(x);
        //one ping timeout 2 sec
    }else{
        post("pcap: No device selected. Selecting device 0..");
        pcap_device_num(x,0);
        //x->x_dev=NULL;
        //x->x_default_dev=0;
    }

}

//look for all computer devices
void pcap_device_find(t_pcap_device *x){
       // Retrieve the system network device list
    if (pcap_findalldevs(&x->x_all_devs, x->x_pcap_pd.x_errbuf2) == -1) {
        error("pcap: Retrieving system network devices...\n");
        return;
    }
    if (x->x_all_devs) {
        // Count how many devices are discovered
        int num = 0;
        pcap_if_t* d;
        post("pcap: LIST of system DEVICES:");
        for(d=x->x_all_devs; d; d=d->next) {
            post("pcap:       %d: %s", num, d->name);
            num++;
        }
        x->x_num_of_devs=num;
        post("pcap: Total number of devices: %d",x->x_num_of_devs);

    }else {
        post("pcap: No network interface detected.");
        post("pcap: Make sure you have enough rights.");
        return;
    }
}

//show selected device basic info
void pcap_device_dinfo(t_pcap_device *x)
{
    if (x->x_dev == NULL) {
        post("pcap: No device selected.");
    }else{
        pcap_device_net_info(x);
        //
        post("pcap: DEVICE INFO:");
        post("pcap:       Name: %s",x->x_dev);
        post("pcap:       IPv4 Address %s", x->x_host_ip);
        post("pcap:       Network Address: %s", x->x_host_net);
        post("pcap:       Netmask: %s", x->x_host_mask);
    }
}

//looks for selected device network information
void pcap_device_net_info(t_pcap_device *x)
{
    bpf_u_int32     dmask;			    /* subnet mask */
    bpf_u_int32     dip;			    /* net addr */
    struct in_addr tmp,tmp2;

    if (x->x_default_dev==0){
        post("pcap: No device selected. Selecting device 0..");
        pcap_device_num(x,0);
    }

    //get ipv4 addr for device
    pcap_device_ipaddr4(x);

    if (pcap_lookupnet(x->x_dev, &dip, &dmask, x->x_pcap_pd.x_errbuf) == -1) {
        error("pcap: Couldn't get info for device %s: %s",x->x_dev, x->x_pcap_pd.x_errbuf);
        post("pcap: Selecting device 0..");
        pcap_device_num(x,0);
    }
    else{
        x->x_pcap_pd.x_net=dip;
        x->x_pcap_pd.x_mask=dmask;
        tmp.s_addr=dip;
        tmp2.s_addr=dmask;
        sprintf(x->x_host_net, "%s", inet_ntoa(tmp));
        sprintf(x->x_host_mask, "%s", inet_ntoa(tmp2));
    }
}

//looks for selected device ip address
void pcap_device_ipaddr4(t_pcap_device *x)
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
void pcap_device_host_name(t_pcap_device *x){
    if (gethostname(x->x_host_name, 32)==-1){
        error("pcap: Can't get hostname.");
    }
}


void *pcap_device_new(t_symbol *s)
{
    t_pcap_device *x = (t_pcap_device *)pd_new(pcap_device_class);
    floatinlet_new(&x->x_obj, &x->x_pcap_pd.x_loop);
    x->x_outlet1 = outlet_new(&x->x_obj, &s_float);	            /*connection status */
    x->x_pcap_pd.x_outlet2 = outlet_new(&x->x_obj, &s_float);             /*packet number*/
    x->x_pcap_pd.x_outlet3 = outlet_new(&x->x_obj, &s_float);             /*Ethernet Info*/
    x->x_pcap_pd.x_outlet4 = outlet_new(&x->x_obj, &s_symbol);            /*IP protocol*/
    x->x_pcap_pd.x_outlet5 = outlet_new(&x->x_obj, &s_symbol);            /*source IP address*/
    x->x_pcap_pd.x_outlet6 = outlet_new(&x->x_obj, &s_symbol);            /*dest IP address*/
    x->x_pcap_pd.x_outlet7 = outlet_new(&x->x_obj, &s_float);             /*src_port number*/
    x->x_pcap_pd.x_outlet8 = outlet_new(&x->x_obj, &s_float);             /*dst_port number*/
    x->x_pcap_pd.x_outlet9 = outlet_new(&x->x_obj, &s_float);             /*packet header*/
    x->x_pcap_pd.x_outlet10 = outlet_new(&x->x_obj, &s_symbol);           /*payload*/

    x->b_out = outlet_new(&x->x_obj, &s_bang);                /*end of capture bang*/

    x->x_clock = clock_new(x, (t_method)pcap_device_tick);

    x->x_pcap_pd.x_filter_exp = (char *)getbytes(MAXFILTERLENG * sizeof(char));

    x->x_pcap_pd.x_num_packets=1;
    x->x_pcap_pd.x_num_packets_count=0;
    x->x_pcap_pd.x_debug=0;
    x->x_connected=0;
    x->x_pcap_pd.x_write_file=0;
    x->x_pcap_pd.x_count=0;
    x->x_pcap_pd.x_timeout=500;
    x->x_pcap_pd.x_delay=100;
    x->x_pcap_pd.x_ip_count=0;
    x->x_pcap_pd.x_tcp_count=0;
    x->x_pcap_pd.x_udp_count=0;
    x->x_pcap_pd.x_icmp_count=0;
    x->x_pcap_pd.x_unk_count=0;
    x->x_pcap_pd.x_maxdata=0;
    x->x_default_dev=0;
    x->x_num_of_devs=0;
    x->x_pcap_pd.x_running=0;
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
    pcap_device_find(x);
    post("pcap: Device %s selected.",x->x_dev);
    pcap_device_net_info(x);
    return (void *)x;
}

void pcap_device_setup(void) {
    pcap_device_class = class_new(gensym("pcap_device"), (t_newmethod)pcap_device_new, 0,
        sizeof(t_pcap_device),0,A_DEFSYMBOL, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_connect, gensym("connect"),0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_disconnect, gensym("disconnect"),0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_capture, gensym("capture"),0);

    class_addbang(pcap_device_class,(t_method)pcap_device_capture);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_numpackets_set, gensym("packets"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_timeout_set, gensym("timeout"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_delay_loop_set, gensym("delay"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_debug_set, gensym("debug"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_reset, gensym("reset"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_info, gensym("info"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_filter_set, gensym("filter"),
        A_GIMME,0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_data_set, gensym("data"),
        A_DEFFLOAT,0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_select, gensym("device"),
        A_GIMME,0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_find, gensym("device_list"),0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_num, gensym("device_num"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_dinfo, gensym("device_info"),0);

    class_addmethod(pcap_device_class,
        (t_method)pcap_device_file_dump_name, gensym("dump"),
        A_GIMME,0);
}
