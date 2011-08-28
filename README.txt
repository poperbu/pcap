PCAP (for pd) 0.0.5  - PD NETWORK SNIFFER, using pcaplib.

Jordi Sala <poperbu@gmail.com> - May2010 -Octuber 2010 
http://musa.poperbu.net/puredata

PCAP (for pd) is a PD network sniffer, based on lippcap, so the use of this external is similar like use tcpdump to sniff the network with PD.

Originally named PDPCAP, the project was renamed PCAP (for pd) to avoid pdp objects confusion, and split the old pdpcap objecct in two diferent objects pcap_device and pcap_file.


LICENSE GPL-> look at LICENSE.txt file in this folder.

PCAP 0.0.5: New features

-pdpcap is renamed to pcap (for pd).
-main old object pdpcap is splitted in two objcets:
	pcap_device->captures network traffic in live mode from a net device (eth0, lo, eth1...).
	pcap_file->reads (captures) network traffic from a pcap file.
-bang for capturing packets.



FEATURES:

-puredata network sniffer lippcap based.
-GNU/Linux and OS X compatible.
-Device selection.
-pcap files read/save.
-traffic filter with pcap filters.
-packets headers and data visualization in PD.

TODO:
-improve code.
-output data in ASCII.
-handle arp, ethernet,.. traffic.
-Control tcp connections, syn, ack's,...
-Traffic injection..

---------------------------------------------------

You need LIBPPCAP -> http://www.tcpdump.org 
(apt-get install, yum..)

NOTES:
-PCAP has been developed and tested in linux-.

-OSX adaptation:
 Nicolas Montgermont <nicolas_montgermont@yahoo.fr> September 2010
 http://nim.on.free.fr

-Any idea or help is welcome->poperbu@gmail.com

INSTALL:
It uses the puredata Makefile Template (Thanks Hans!!)
http://puredata.info/docs/developer/MakefileTemplate

RUN:
For live capture: Open the patch pcap_device-help.pd AS ROOT!! (in linux), and it should work.
In OSX change read permission of net device: udo chmod a+r /dev/bpf*

