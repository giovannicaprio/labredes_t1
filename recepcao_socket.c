/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <netinet/tcp.h> // header tcp
#include <netinet/udp.h> // header udp
#include <netinet/ip6.h> // ipv6 header

#include <netinet/icmp6.h> // header icmpv6

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;
  struct iphdr *ipheader;
  struct ip6_hdr *ip6header;
  struct tcphdr *tcpheader;
  struct udphdr *udpheader;
  struct icmphdr *icmpheader;
  struct icmp6_hdr *icmp6header;

int main(int argc,char *argv[])
{
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "wlp3s0"); // TODO: TROCAO PARA INTERFACE CORRETA
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	uint32_t s_ip;

	int next_header;

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff, sizeof(buff), 0x0);

		// Ethernet
		printf("-->Ethernet \n");
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff[0],buff[1],buff[2],buff[3],buff[4],buff[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff[6],buff[7],buff[8],buff[9],buff[10],buff[11]);
		printf("Type : %x%x \n", buff[12],buff[13]);

		//IPv4
		if (buff[12] == 0x8 && buff[13] == 0x00) {
			// Header ip comeca no byte 14
			ipheader = (struct iphdr*)&buff[14];

			// TODO: falta campo flags e tratar IPV6
			printf("-->IPv4 \n");
			printf("Version : %d \n", ipheader->version);
			printf("IHL : %d \n", ipheader->ihl);
			printf("Type of service %d \n", ipheader->tos);
			printf("Total length : %d\n", ipheader->tot_len);
			printf("Identification : %d \n", ipheader->id);
			printf("Fragment Offset : %d \n", ipheader->frag_off);
			printf("Ttl : %d\n", ipheader->ttl);
			printf("Protocol : %d\n", ipheader->protocol);
			printf("Checksum : %d\n", ipheader->check);
			printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&ipheader->saddr));
			printf("Destination address : %s\n", inet_ntoa(*(struct in_addr *)&ipheader->daddr));

			switch(ipheader->protocol) {
				case 6 : //TCP
					// Header tcp comeca no byte 34
					tcpheader = (struct tcphdr*)&buff[34];
					printf("-->TCP \n");
					printf("Source port : %d \n", tcpheader->source);
					printf("Destination port : %d \n", tcpheader->dest);
					printf("Sequence number : %d \n", tcpheader->seq);
					printf("Acknowledgment number : %d \n", tcpheader->ack_seq);
					printf("Window : %d \n", tcpheader->window);
					printf("Checksum : %d \n", tcpheader->check);
					printf("Urgent pointer : %d \n", tcpheader->urg_ptr);
					break;
				case 17 : // UDP
					udpheader = (struct udphdr*)&buff[34];
					printf("-->UDP \n");
					printf("Source port : %d \n", udpheader->source);
					printf("Destination port : %d \n", udpheader->dest);
					printf("Length : %d \n", udpheader->len);
					printf("Checksum : %d \n", udpheader->source);
					break;
				case 1 : // ICMP
					icmpheader = (struct icmphdr*)&buff[34];
					printf("-->ICMP \n");
					printf("Type : %d \n", icmpheader->type);
					printf("Code : %d \n", icmpheader->code);
					printf("Checksum : %d \n", icmpheader->checksum);
					break;
			}
		
		}
		//IPv6
		else if (buff[12] == 0x86 && buff[13] == 0xdd) {
			ip6header = (struct ip6_hdr*)&buff[14];

			// TODO: ip6_vfc contem version e traffic class(separar)
			printf("-->IPv6 \n");
			printf("Version : %d \n", ip6header->ip6_vfc);
			printf("Flow label : %d \n", ip6header->ip6_flow);
			printf("Payload length : %d \n", ip6header->ip6_plen);
			printf("Next header : %d \n", ip6header->ip6_nxt);
			printf("Hoop limit : %d \n", ip6header->ip6_hlim);

			printf("Source address : %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x \n", buff[22],buff[23],buff[24],buff[25],
			buff[26],buff[27],buff[28],buff[29],buff[30],buff[31],buff[32],buff[33],buff[34],
			buff[35],buff[36],buff[37]);
			printf("Source address : %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x \n", buff[38],buff[39],buff[40],buff[41],
			buff[42],buff[43],buff[44],buff[45],buff[46],buff[47],buff[48],buff[49],buff[50],
			buff[51],buff[52],buff[53]);

			// ICMPv6
			if (ip6header->ip6_nxt == 58) {
				icmp6header = (struct icmp6_hdr*)&buff[54];

				printf("-->ICMPv6 \n");
				printf("Type : %d \n", icmp6header->icmp6_type);
				printf("Code : %d \n", icmp6header->icmp6_code);
				printf("Checksum : %d \n", icmp6header->icmp6_cksum);
			}
		}
		// ARP
		else if (buff[12] == 0x08 && buff[13] == 0x06) {

		}

		printf("------------------------\n\n");
	}
}	