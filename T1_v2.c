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

  struct entidadeIP
  {
	char *nome;
	int qtd;
  };

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

  int globalIPV4 = 0;
  int globalIPV6 = 0;
  
  int totaisTransmissao[5];
  int totaisRecepco[5];
  
  struct entidadeIP sendersIPV4[999];
  struct entidadeIP receiversIPV4[999];

  struct entidadeIP sendersIPV6[999];
  struct entidadeIP receiversIPV6[999];

  //metodos para retornar os nomes dos protocolos mais usados
  int maiorTransmissao (int vetor[]);
  int maiorRecepcao (int vetor[]);

  //metodos para retornar os nomes dos protocolos ips mais usados 
  char * maiorIPV4(struct entidadeIP array[]);
  char * maiorIPV6(struct entidadeIP array[]);

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

    char nomesTransmissao[][10] = { "TCP", "UDP" };
    char nomesRecepcao[][10] = { "ICMP", "ICMPv6" };


    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp4s0"); // TODO: TROCAO PARA INTERFACE CORRETA
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	int executions = 0;
	// recepcao de pacotes
	while (executions < 20) {
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
            countIPv4 += 1;

            //cria o objeto para o ip4 e coloca no array sem duplicar
            //FIQUEI com uma pequena duvida 
            struct entidadeIP sIPV4;
			
				sIPV4.nome = inet_ntoa(*(struct in_addr *)&ipheader->saddr);

			    //verificador para informar se depois do loop foi incrementado o que se tem
			    // se 0 add novo
			    int verificadorSender = 0;
			    for(int i = 0; i <globalIPV4 ; i++ ){
			      if(sendersIPV4[i].nome == sIPV4.nome){
			        //ja tem na coleção, apenas incrementa a qtd
			        sendersIPV4[i].qtd += 1;
			        verificadorSender += 1;
			      } 
			  	}
			  	if(verificadorSender == 0){ //add novo no array
			  		sIPV4.qtd = 1;
			   	 	sendersIPV4[globalIPV4] = sIPV4;
			  	}

			 struct entidadeIP rIPV4;
			     rIPV4.nome = inet_ntoa(*(struct in_addr *)&ipheader->daddr);
			    //verificador para informar se depois do loop foi incrementado o que se tem
			    // se 0 add novo
			    int verificadorReceiver = 0;
			    for(int i = 0; i <globalIPV4 ; i++ ){
			      if(receiversIPV4[i].nome == rIPV4.nome){
			        //ja tem na coleção, apenas incrementa a qtd
			        receiversIPV4[i].qtd += 1;
			        verificadorReceiver += 1;
			      } 
			  	}
			  	if(verificadorReceiver == 0){ //add novo no array
			  		rIPV4.qtd = 1;
			   	 	receiversIPV4[globalIPV4] = rIPV4;
			  	}  	
			     
			    globalIPV4 += 1;

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
		executions++;
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

            struct entidadeIP sIPV6;
			sIPV6.nome = buff[22],buff[23],buff[24],buff[25],
			buff[26],buff[27],buff[28],buff[29],buff[30],buff[31],buff[32],buff[33],buff[34],
			buff[35],buff[36],buff[37];

			    //verificador para informar se depois do loop foi incrementado o que se tem
			    // se 0 add novo
			    int verificadorSender6 = 0;
			    for(int i = 0; i <globalIPV6 ; i++ ){
			      if(sendersIPV4[i].nome == sIPV6.nome){
			        //ja tem na coleção, apenas incrementa a qtd
			        sendersIPV6[i].qtd += 1;
			        verificadorSender6 += 1;
			      } 
			  	}
			  	if(verificadorSender6 == 0){ //add novo no array
			  		sIPV6.qtd = 1;
			     	sendersIPV6[globalIPV6] = sIPV6;

			  	}

			 struct entidadeIP rIPV6;
			     rIPV6.nome = buff[38],buff[39],buff[40],buff[41],
			buff[42],buff[43],buff[44],buff[45],buff[46],buff[47],buff[48],buff[49],buff[50],
			buff[51],buff[52],buff[53];
			    //verificador para informar se depois do loop foi incrementado o que se tem
			    // se 0 add novo
			    int verificadorReceiver6 = 0;
			    for(int i = 0; i <globalIPV6 ; i++ ){
			      if(receiversIPV6[i].nome == rIPV6.nome){
			        //ja tem na coleção, apenas incrementa a qtd
			        receiversIPV6[i].qtd += 1;
			        verificadorSender6 += 1;
			      } 
			  	}
			  	if(verificadorReceiver6 == 0){ //add novo no array
			  		rIPV6.qtd = 1;
			   	 	receiversIPV6[globalIPV6] = rIPV6;
			  	}  	
			     			     
				globalIPV6 += 1;


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
			executions++;
		}
		// ARP
		else if (buff[12] == 0x08 && buff[13] == 0x06) {
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

			executions++;
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

		printf("Protocolo de aplicação mais usado nas transmissões: %s \n", nomesTransmissao[maiorTransmissao(totaisTransmissao)]);
		printf("Protocolo de aplicação mais usado nas recepções: %s \n", nomesRecepcao[maiorRecepcao(totaisRecepco)]);

        printf("Endereço IPv4 da máquina que mais transmitiu pacotes: %s \n", maiorIPV4(sendersIPV4));
		printf("Endereço IPv4 da máquina que mais recebeu pacote: %s \n", maiorIPV4(receiversIPV4));

		printf("Endereço IPv6 da máquina que mais transmitiu pacotes: %c \n", maiorIPV6(sendersIPV6));
		printf("Endereço IPv6 da máquina que mais recebeu pacote: %c \n", maiorIPV6(receiversIPV6));
}

int maiorTransmissao(int vetor[])
{
    int maior  = vetor[0];
    int idMaior = 0;
    size_t i = 0;
	
	for(i = 0; i < sizeof(vetor) / sizeof(vetor[0]);i++){
        if(vetor[i] > maior){
            maior = vetor[i]; 
            idMaior = i;
        } 
    }
    return idMaior;

}

int maiorRecepcao(int vetor[])
{
    int maior  = vetor[0];
    int idMaior = 0;
    size_t i = 0;
	for(i = 0; i < sizeof(vetor) / sizeof(vetor[0]);i++){
        if(vetor[i] > maior)
            maior = vetor[i]; 
            idMaior = i; 
    }
    return idMaior;
}

char* maiorIPV4(struct entidadeIP array[])
{

  int maior = array[0].qtd;
  char *nomeMaior = array[0].nome;
  for(int i = 0; i <globalIPV4; i++){
    if(array[i].qtd > maior){
      maior = array[i].qtd;
      nomeMaior = array[i].nome;
    }   
  }

  return nomeMaior;
}

char* maiorIPV6(struct entidadeIP array[])
{

  int maior = array[0].qtd;
  char * nomeMaior = array[0].nome;
  for(int i = 0; i <globalIPV6; i++){
    if(array[i].qtd > maior){
      maior = array[i].qtd;
      nomeMaior = array[i].nome;
    }   
  }
  return nomeMaior;
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