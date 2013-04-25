/*

 Simple Packet Generator - C Language - Linux/x86
 Copyright (C) 2013 Danilo P.C.

   DaNotKnow@gmail.com

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/



/*
	Special Thanks to:
	Cooler_ (c00f3r.gmail.com)
	Geyslan (geyslan@gmail.com)
	Alfredo (1phee3@gmail.com)
	Silver Moon (m00n.silv3r@gmail.com)
*/

//------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------//

/*
	Programa para geracao de pacotes IP simples usando Raw Sockets. Atualmente somente gera protocolos udp, porem irei melhora-lo logo logo
	Tentei deixar o codigo o mais didatico possivel. Nota: há alguns pontos que podem causar buffer overflow ( just dont care about it now)
	
	Duvidas? mail me: DaNotKnow@gmail.com
	Se voce nao conhece sockets, raw sockets, protocolos e encapsulamento, consulte os seguintes sites antes de ver o codigo:
	[1] http://www.tenouk.com/Module39.html
	[2] http://www.tenouk.com/Module42.html
	[3] http://csis.bits-pilani.ac.in/faculty/dk_tyagi/Study_stuffs/raw.html
	[4] https://github.com/CoolerVoid/Hyde/blob/master/hyde.c#L243
	[5] http://www.binarytides.com/raw-sockets-c-code-linux/
*/

//------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------//

#include <stdio.h>         //Para a funcao printf
#include <string.h>        //memset
#include <sys/socket.h>    //Para usar as funcoes e estruturas relacionadas aos sockets
#include <stdlib.h>	  //Para a funcao exit()
#include <netinet/tcp.h>   //Prove uma estrutura de cabecalho tcp. Nao utilizei esta estrutura diretamente.
#include <netinet/ip.h>    //Prove uma estrutura de cabecalho ip.
#include "headers.h"

#define PAYLOAD "ABCDEFGHIJKLMNOPQRSTUVXZ"   //Define o payload do pacote


//------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------//


// Funcao usada para calcular o checksum dos cabeçalhos ip
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    return(answer);
}

//------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------//


int main( int argc, char **argv)
{
	int status;			// usada para armazenar o retorno das funcoes
	struct iphdr *ip;		// Ponteiro para minha estrutura que representa um cabecalho IP
	struct udpheader *udp;		// Ponteiro para minha estrutura que reprenseta um cabecalho udp
	int sockfd;			// usada para armazenar um socket file descriptor
	int one = 1;			// Usado para setar a opcao IP_HDRINCL do socket para dizer ao kernel que os header ja estao inclusos no pacote
	struct sockaddr_in dest;	// Usado para armazenar os dados para envio para o destinatario
	char *data;                     // Usado para transferir o payload no pacote
	char packet[ sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(PAYLOAD) ];	//Usado para armazenar o pacote em si

	//Checa se os argumentos foram passados "corretamente"
	if( argc != 5){
		printf("Uso: ./simpleRaw [Ip Origem] [Porta Origem] [Ip Destino] [Porta Destino]\n");
		printf("Exemplo: ./simpleRaw 1.2.3.4 22 8.8.8.8 53\n");
		printf("Analise a saida no wireshark!\n");
		exit(1);
	}

	//Cria um socket informando ao kernel que irei utilizar udp como protocolo de camada 4
	sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sockfd == -1){
		printf("Erro ao iniciar o socket\n");
		exit(1);
	}

	//Seta a opcao IP_HDRINCL
	status = setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);
	if (status == -1){
                printf("Erro ao setar a opcao HDRINCL do socket\n");
                exit(1);
        }

	//zera a stack relacionada ao packet
	memset( packet, 0, sizeof(packet) );

	//Monta os cabecalhos no packet
	// [ [IP HEADER] [UDP HEADER] [PAYLOAD] ]
	ip = (struct iphdr *)packet;
	udp = (struct udpheader *) (packet + sizeof(struct iphdr) );
	data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct udpheader) );
	strcpy(data, PAYLOAD);

	//Preenche o cabecalho IP
	ip->version = 4;		//IPv4
        ip->ihl = 5;			//Tamanho do cabecalho, minimo eh 5
        ip->tos = 0;	//Tipo de servico, default eh 0 que reprsenta opcoes normais
        ip->tot_len = sizeof(packet);  //tamanho do datagrama
        ip->id = htonl(1234);   // Numero de identificacao do pacote
        ip->frag_off = 0;		      // Flags, zero representa reservado (Preciso pesquisar mrlhor isto)
     //   ip->ip_fragmentOffset = 0;	      // Caso haja fragmentacao de datagramas, este numero representa a posicao do fragmento no datagrama
        ip->ttl = 255;	      // Maximo 255
        ip->protocol = IPPROTO_UDP;	      // Apresenta UDP como protocolo a ser usado na proxima camada
        ip->check = 0;	      // Calculado depois
        ip->saddr = inet_addr( argv[1] );  //Ip de origem ( spoofing ocorre aqui)
        ip->daddr = inet_addr( argv[3] ); //IP de destino

	//Preenche o cabecalho UDP
	udp->udp_sourcePortNumber = htonl( atoi(argv[2]) );        //Porta de origem
	udp->udp_destinationPortNumber = htonl( atoi(argv[4]) );   //Porta de destino
	udp->udp_length = htonl( sizeof(struct udpheader) ); //Tamanho do cabecalho udp
	udp->udp_checksum = 0;				     //Calculado depois

	//Calcula os checksums
	ip->check = csum((unsigned short *)packet, ip->tot_len);   //Calcula o checksum do cabecalho ip
	udp->udp_checksum = csum((unsigned short *)udp, udp->udp_length);	      //Calcula do checksum do cabecalho udp

	//Armazena os dados do destino
	dest.sin_family = AF_INET;				// Address Family Ipv4
	dest.sin_port = htons (atoi( argv[4] ) ) ; 		// Porta de destino, redundante e ja tenho este dado amazenado na estrutura udp, mas por fins didaticos repeti aqui  
	dest.sin_addr.s_addr = inet_addr( argv[3] );		// Endereço para onde se quer enviar o pacote 


	//Loop principal
	int count = 0;
	while( count < 100){

		// Envia os pacotes
		status = sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest) );
		if(status <0){
			printf("Erro ao enviar os pacotes\n");
			exit(1);
		}
		count++;
	}
	printf("Enviados %d pacotes de tamanho: %d, olhe o Wireshark!!!\n", count, ip->tot_len);

exit(0);
}
