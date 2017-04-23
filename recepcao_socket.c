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

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff, sizeof(buff), 0x0);

		// Ethernet
		printf("Ethernet \n");
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff[0],buff[1],buff[2],buff[3],buff[4],buff[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff[6],buff[7],buff[8],buff[9],buff[10],buff[11]);
		printf("Type : %x%x \n", buff[12],buff[13]);
		printf("------------------------\n");

		//se for ip
		if (buff[12] == 0x8 && buff[13] == 0x0) {
			ipheader = (struct iphdr*)buff;

			// TODO: falta campo flag aqui
			printf("IPv4 \n");
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

			//TCP
			if (ipheader->protocol == 6) {
				// printf("Source port : %d \n", );
			}
		}

		printf(" \n");
	}
}	