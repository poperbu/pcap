/* 		PCAP for PD 0.0.5: pcap_file.c 		                                    */
/*		Jordi Sala poperbu@gmail.com 20100929                 		            */
/*										                                        */
/* --------------------------  pcap_file  ------------------------------------- */
/*                                                                              */
/* Is an External Object for pd that uses lipcap to read pcap files and         */
/* analizing network packets.                                   		        */
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


static t_class *pcap_file_class;

typedef struct _pcap_file {
    t_object  x_obj;
    t_outlet *x_outlet1;        /*file open status*/
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
    int         x_file_ok;
    int         x_default_file;           /*default or custom file*/
    int         x_reading_file;         /*pcap reading file*/
    char        *x_default_filename;           /*default filename*/
    char        *x_rfilename;      //pcap source file to read

} t_pcap_file;


void pcap_file_tick(t_pcap_file *x);



//PCAP FILE READ
void pcap_file_read(t_pcap_file *x, t_symbol *s, int argc, t_atom *argv)
{
    t_float c;
    int next_res;
    next_res=0;
    if (x->x_reading_file == 1){
        post("pcap: A file is already opened.");
    }else{
        if(argc == 1){
            s=atom_getsymbol(argv);
            x->x_rfilename=s->s_name;
            post("pcap: File for reading %s selected.", x->x_rfilename);
            x->x_file_ok=1;
            x->x_reading_file=1;
        }else{
            if ( x->x_default_filename == NULL){
                post("pcap: No default file name.");
                x->x_reading_file=0;
                x->x_file_ok=0;
            }else{
                post("pcap: Selecting default filename %s",x->x_default_filename);
                x->x_rfilename=x->x_default_filename;
                x->x_file_ok=1;
                x->x_reading_file=1;
            }
        }
        if(x->x_file_ok==1){
            if (x->x_pcap_pd.x_num_packets == 0){x->x_pcap_pd.x_num_packets=1;}
            x->x_reading_file=1;
            x->x_pcap_pd.x_handle=pcap_open_offline(x->x_rfilename, x->x_pcap_pd.x_errbuf);
            if(!x->x_pcap_pd.x_handle){
                error("pcap: Error opening %s file.",x->x_rfilename);
                x->x_reading_file=0;
            }else{
                post("pcap: Analizing %s file....",x->x_rfilename);
                /* compile the filter expression */
                if (pcap_compile(x->x_pcap_pd.x_handle, &x->x_pcap_pd.x_fp, x->x_pcap_pd.x_filter_exp, 0, x->x_pcap_pd.x_net ) == -1) {
                    error("pcap: Couldn't parse filter %s: %s", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                    x->x_reading_file=0;
                }else{
                    post("pcap: Filter Parsed %s: %s -> Ok", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                    /* apply the compiled filter */
                    if (pcap_setfilter(x->x_pcap_pd.x_handle, &x->x_pcap_pd.x_fp) == -1) {
                        error("pcap: Couldn't install filter %s: %s", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                        x->x_reading_file=0;
                    }else{
                        post("pcap: Filter Installed  %s: %s-> Ok", x->x_pcap_pd.x_filter_exp, pcap_geterr(x->x_pcap_pd.x_handle));
                        x->x_reading_file=1;
                        //outlet_float(x->x_outlet1,1);
                        pcap_dumping_file(&x->x_pcap_pd);
                    }
                }
            }
        }else{
            post("pcap: No file to read.");
        }
    }
    c=x->x_reading_file;
    outlet_float(x->x_outlet1,c);
    return;
}

//CLOSE PCAP FILE
void pcap_file_close(t_pcap_file *x){
    t_float c;
    int conn;
    conn=0;
        post("pcap: device was not connected NOT connected.");
        if (x->x_reading_file == 1){
            pcap_close(x->x_pcap_pd.x_handle);
            x->x_reading_file=0;
            c=x->x_reading_file;
            outlet_float(x->x_outlet1,c);
            post("pcap: Ok file %s closed.",x->x_rfilename);

            conn=1;
        }else{
            post("pcap: No file opened.");
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
void pcap_file_capture(t_pcap_file *x){
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
    if (x->x_reading_file == 0){
        error("pcap: NOT reading file.");
        x->x_pcap_pd.x_running=0;
    }else{
        outlet_float(x->x_outlet1,1);
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
void pcap_file_dump_name(t_pcap_file *x, t_symbol *s, int argc, t_atom *argv)
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
void pcap_file_numpackets_set(t_pcap_file *x, t_floatarg f)
{
    x->x_pcap_pd.x_num_packets=f;
    post("pcap: Number of packets:%d",x->x_pcap_pd.x_num_packets);
}

//set loop (continous) capture mode
void pcap_file_loop_set(t_pcap_file *x, t_floatarg f)
{
    x->x_pcap_pd.x_loop=f;
    x->x_pcap_pd.x_num_packets=1;
    post("pcap: Loop set to:%d",x->x_pcap_pd.x_loop);
    post("pcap: Number of packets (by default in loop mode):%d",x->x_pcap_pd.x_num_packets);
}

//sets timout
void pcap_file_timeout_set(t_pcap_file *x, t_floatarg f)
{
    x->x_pcap_pd.x_timeout=f;
    post("pcap: Timeout set to:%d",x->x_pcap_pd.x_timeout);
}

//packet filter setting
void pcap_file_filter_set(t_pcap_file *x, t_symbol *s, int argc, t_atom *argv)
{
    pcap_filter_set(&x->x_pcap_pd,s,argc,argv);
    if (x->x_reading_file == 1){
        post("pcap: Re-open reading file to apply new filter.");
    }
}

//time delay
void pcap_file_delay_loop_set(t_pcap_file *x, t_floatarg f)
{
    x->x_pcap_pd.x_delay=f;
    post("pcap: Delay set to:%d",x->x_pcap_pd.x_delay);
}

//set data to output
void pcap_file_data_set(t_pcap_file *x, t_floatarg f)
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
void pcap_file_debug_set(t_pcap_file *x, t_floatarg f)
{
    if (f==0 || f==1){
        x->x_pcap_pd.x_debug=f;
        post("pcap: Debug set to:%d",x->x_pcap_pd.x_debug);
    }
    else{
        error("pcap: Wrong value for debug (0 or 1)");
    }
}

//prints pcap_file info
void pcap_file_info(t_pcap_file *x)
{
    post("pcap: PDPCAP INFO:");

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

void pcap_file_tick(t_pcap_file *x)
{
  pcap_file_capture(x);
}


//reset to default settings
void pcap_file_reset(t_pcap_file *x)
{
    x->x_pcap_pd.x_num_packets=1;
    x->x_pcap_pd.x_num_packets_count=0;
    x->x_pcap_pd.x_debug=0;

    x->x_reading_file=0;
    x->x_pcap_pd.x_write_file=0;
    x->x_pcap_pd.x_count=0;
    x->x_pcap_pd.x_timeout=500;
    x->x_pcap_pd.x_delay=100;
    x->x_pcap_pd.x_ip_count=0;
    x->x_pcap_pd.x_tcp_count=0;
    x->x_pcap_pd.x_udp_count=0;
    x->x_pcap_pd.x_icmp_count=0;
    x->x_pcap_pd.x_unkip_count=0;
    x->x_pcap_pd.x_unk_count=0;
    x->x_pcap_pd.x_arp_count=0;
    x->x_pcap_pd.x_rarp_count=0;
    x->x_pcap_pd.x_maxdata=0;


    pcap_file_info(x);
}


void *pcap_file_new(t_symbol *s)
{
    t_pcap_file *x = (t_pcap_file *)pd_new(pcap_file_class);
    floatinlet_new(&x->x_obj, &x->x_pcap_pd.x_loop);
    x->x_outlet1 = outlet_new(&x->x_obj, &s_float);	            /*file  status */
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

    x->x_clock = clock_new(x, (t_method)pcap_file_tick);

    x->x_pcap_pd.x_filter_exp = (char *)getbytes(MAXFILTERLENG * sizeof(char));

    x->x_pcap_pd.x_num_packets=1;
    x->x_pcap_pd.x_num_packets_count=0;
    x->x_pcap_pd.x_debug=0;
    x->x_reading_file=0;
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
    x->x_default_file=0;
    x->x_pcap_pd.x_running=0;
    t_symbol *filesel;
    filesel=s;
    x->x_rfilename=s->s_name;
    if (s->s_name[0]){
        x->x_rfilename=filesel->s_name;
        x->x_default_filename=filesel->s_name;
        x->x_default_file=1;

    }else{
        x->x_rfilename=NULL;
    }

    post("pcap: File %s selected.",x->x_rfilename);

    pcap_file_read(x,s,&x->x_rfilename,1);

    return (void *)x;
}

void pcap_file_setup(void) {
    pcap_file_class = class_new(gensym("pcap_file"), (t_newmethod)pcap_file_new, 0,
        sizeof(t_pcap_file),0,A_DEFSYMBOL, 0);


    class_addmethod(pcap_file_class,
        (t_method)pcap_file_close, gensym("close"),0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_capture, gensym("capture"),0);

    class_addbang(pcap_file_class,(t_method)pcap_file_capture);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_numpackets_set, gensym("packets"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_timeout_set, gensym("timeout"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_delay_loop_set, gensym("delay"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_debug_set, gensym("debug"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_reset, gensym("reset"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_info, gensym("info"),
        A_DEFFLOAT, 0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_filter_set, gensym("filter"),
        A_GIMME,0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_data_set, gensym("data"),
        A_DEFFLOAT,0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_read, gensym("read"),
        A_GIMME,0);

    class_addmethod(pcap_file_class,
        (t_method)pcap_file_dump_name, gensym("dump"),
        A_GIMME,0);
}
