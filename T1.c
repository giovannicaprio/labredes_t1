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
#include <net/if_arp.h> // arp header

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
  struct arphdr *arpheader;
  
  int totalPacotes;
  int countIPv4;
  int countIPv6;
  int countTCP;
  int countUDP;
  int countICMP;
  int countICMPv6;
  int countARP;
  int totaisTransmissao[5];
  int totaisRecepco[5];

  int maior (int vetor[]);
  char * application_protocol(int protocol);

int main(int argc,char *argv[])
{
    totalPacotes = 0;
    countIPv4 = 0;
    countIPv6 = 0;
    countTCP = 0;
    countUDP = 0;
    countICMP = 0;
    countICMPv6 = 0;
    countARP = 0;
    
    totaisTransmissao[0] = countTCP;
    totaisTransmissao[1] = countUDP;

    totaisRecepco[0] = countICMP;
    totaisRecepco[1] = countICMPv6;


    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp3s0"); // TODO: TROCAO PARA INTERFACE CORRETA
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
		if (buff[12] == 0x08 && buff[13] == 0x00) {
			// Header ip comeca no byte 14
			ipheader = (struct iphdr*)&buff[14];

			// TODO: falta campo flags
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
            countIPv4 +=countIPv4;

			switch(ipheader->protocol) {
				case 6 : //TCP
					// Header tcp comeca no byte 34
					tcpheader = (struct tcphdr*)&buff[34];
					printf("-->TCP \n");
					printf("Source port : %d \n", tcpheader->source);
					printf("Destination port : %d %s \n", tcpheader->dest, application_protocol(tcpheader->dest));
					printf("Sequence number : %d \n", tcpheader->seq);
					printf("Acknowledgment number : %d \n", tcpheader->ack_seq);
					printf("Window : %d \n", tcpheader->window);
					printf("Checksum : %d \n", tcpheader->check);
					printf("Urgent pointer : %d \n", tcpheader->urg_ptr);
					countTCP += 1;
                    totalPacotes += +1;
					break;
				case 17 : // UDP
					udpheader = (struct udphdr*)&buff[34];
					printf("-->UDP \n");
					printf("Source port : %d \n", udpheader->source);
					printf("Destination port : %d \n", udpheader->dest);
					printf("Length : %d \n", udpheader->len);
					printf("Checksum : %d \n", udpheader->source);
					countUDP += 1;
                    totalPacotes += +1;
					break;
				case 1 : // ICMP
					countICMP += 1;
                    totalPacotes += +1;
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
			countIPv6 += 1;
            totalPacotes += +1;
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
			printf("Destination address : %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x \n", buff[38],buff[39],buff[40],buff[41],
			buff[42],buff[43],buff[44],buff[45],buff[46],buff[47],buff[48],buff[49],buff[50],
			buff[51],buff[52],buff[53]);

			// ICMPv6
			if (ip6header->ip6_nxt == 58) {
				icmp6header = (struct icmp6_hdr*)&buff[54];

				printf("-->ICMPv6 \n");
				printf("Type : %d \n", icmp6header->icmp6_type);
				printf("Code : %d \n", icmp6header->icmp6_code);
				printf("Checksum : %d \n", icmp6header->icmp6_cksum);
				countICMPv6 += 1;
                totalPacotes += +1;
			}
		}
		// ARP
		if (buff[12] == 0x08 && buff[13] == 0x06) {
			arpheader = (struct arphdr*)&buff[14];
			printf("-->ARP \n");
			printf("Hardware address type : %d \n", arpheader->ar_hrd);
			printf("Protocol address type : %d \n", arpheader->ar_pro);
			printf("Hardware address length : %d \n", arpheader->ar_hln);
			printf("Protocol address length : %d \n", arpheader->ar_pln);
			printf("Operation : %x \n", buff[21]);
			printf("Source hardware address: %x:%x:%x:%x:%x:%x \n", buff[22],buff[23],buff[24],buff[25],buff[26],buff[27]);
			printf("Source address : %s\n", inet_ntoa(*(struct in_addr *)&buff[28]));
			printf("Target hardware address: %x:%x:%x:%x:%x:%x \n", buff[32],buff[33],buff[34],buff[35],buff[36],buff[37]);
			printf("Destination address : %s\n", inet_ntoa(*(struct in_addr *)&buff[38]));
			countARP += 1;
            totalPacotes += +1;
		}

		printf("-------------------------------------------------------\n\n");
	}


        printf("::: Estatísticas totais de uso ::: \n\n");
		printf("Total de pacotes capturados %i = \n" , totalPacotes );
		printf("Total de pacotes ARP capturados = %i \n", countARP );
		printf("Total de pacotes IPv4 capturados = %i \n", countIPv4 );
		printf("Total de pacotes IPv6 capturados = %i \n", countIPv6 );
		printf("Total de pacotes ICMP capturados = %i \n", countICMP );
		printf("Total de pacotes ICMPv6 capturados = %i \n", countICMPv6 );
		printf("Total de pacotes TCP capturados = %i \n", countTCP );
		printf("Total de pacotes UDP capturados = %i \n", countUDP );

		printf("-------------------------------------------------------\n\n");

   		printf("Protocolo de aplicação mais usado nas transmissões: %i \n", maior(totaisTransmissao));
		printf("Protocolo de aplicação mais usado nas recepções: %i \n", maior(totaisRecepco));
        printf("Endereço IP da máquina que mais transmitiu pacotes: %s \n");
		printf("Endereço IP da máquina que mais recebeu pacote: %i \n");
}

int maior(int vetor[])
{
    int maior  = vetor[0];
    for(int i = 1; i <sizeof(vetor);i++){
        if(vetor[i] > maior)
            maior = vetor[i]; 
    }
    return maior;

}

char* application_protocol(int protocol)
{
	char *p;

	switch(protocol) {
		case 7 :
			p = "echo";
			break;
		case 110 :
			p = "pop3";
		 	break;
		case 19 : 
			p = "chargen";
			break;
		case 111 : 
			p = "sunrpc";
			break;
		case 20 : 
			p = "ftp-data";
			break;
		case 119 : 
			p = "nntp";
			break;
		case 21 :
			p =  "ftp-control";
			break;
		case 139 : 
			p = "netbios-ssn";
			break;
		case 22 :
			p = "ssh";
			break;
		case 143 :
			p = "imap";
			break;
		case 23 : 
			p = "telnet";
			break;
		case 179 :
			p = "bgp";
			break;
		case 25 :
			p = "smtp";
			break;
        case 389 : 
			p = "ldap";
			break;
		case 53 : 
			p = "domain";
			break;
		case 443 :
			p = "https";
			break;
		case 79 :
			p = "finger";
			break;
		case 80 : 
			p= "http";
			break;
		case 445 :
			p = "microsoft-ds";
			break;
		case 1080 :
			p = "socks";
			break;
		default :
			p = "";
			break;
	}

	return p;
}
