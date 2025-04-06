# PCAP-programming
노션 링크 - https://www.notion.so/PCAP-Programming-1cd0d4a3e0ac800c96b2cb376584caee?pvs=4
# 1. 개요

C, C++ 기반 PCAP API를 이용하여 패킷 정보를 출력하는 코드를 작성한다.

기존 sniff_improved.c, myheader.h 코드를 참고하여 작성하였다.

sniff_improved.c에서 이미 Ethernet과 IP 헤더를 처리하였으므로 myheader.h에서 TCP 헤더 구조체를 가져오고 앞서 처리한  Ethernet과 IP 헤더를 처리한 방법과 유사하게 TCP 헤더 또한 처리한다.

message를 출력하기 위해 Ethernet, IP, TCP 헤더의 길이를 가지고 있다가 전체 패킷 길이에서 헤더의 길이를 빼서 패킷에서 message의 시작위치를 찾고 출력한다.

깃헙 링크 : https://github.com/wiker0712/PCAP-programming

# 2.  코드 구현

### 1) 구조체

구조체는 myheader.h에 있는 정보를 바탕으로 작성되었다.

- ethheader 구조체
    
    ```c
    /* Ethernet header */
    struct ethheader {
      u_char  ether_dhost[6]; /* destination host address */
      u_char  ether_shost[6]; /* source host address */
      u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
    };
    ```
    

Link 계층의 Ethernet 헤더 구조체이다. 목적지/출발지 MAC 주소와 다음 프로토콜 타입으로 구성되어 있다.

- ipheader 구조체

```c
/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};
```

Network 계층의 IP 헤더 구조체이다. IP의 출발지/목적기 주소, 다음 프로토콜 타입, IP헤더 길이 등으로 구성되어 있다.

- tcpheader 구조체

```c
/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};
```

Transport 계층의 TCP 구조체이며 출발지/목적지 포트 번호등으로 구성되어 있다.

### 2) main

```c
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
```

main 코드는 sniff_improved.c와 거의 유사하며 패킷을 캡처하고 got_packet 함수로 전달하여 패킷을 분석한다. 주요 변경점으로는 filter_exp[] = "tcp"; 으로 변경하여 TCP Protocol 대상으로만 패킷을 받게 되어있다.

### 3) got_packet 함수

sniff_improved.c에서 Ethernet , IP 헤더 파싱하는 부분이 있었는데 추가적으로 TCP 헤더 또한 처리하고 Message도 처리하여 출력한다.

```c
    	//tcp header
    	struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader)+ipHeaderLength);
    	int tcpHeaderLength = TH_OFF(tcp)*4;
```

TCP 헤더는 IP헤더 뒤에 존재한다. 이를 이용하여 앞서 진행한 Ethernet, IP 헤더 파싱처럼 TCP 헤더 또한 파싱한다.

TCP 헤더 길이 또한 따로 변수에 저장하여 둔다. 이는 이후 Message를 출력할 때 헤더의 길이를 알아야 헤더를 제외한 데이터를 출력할 수 있기 떄문에 기록하여 둔다.

```c
// message
    	int HEAD_SIZE = sizeof(struct ethheader) + ipHeaderLength + tcpHeaderLength;
    	int payloadLength = header->len - HEAD_SIZE;
    	const u_char *payload = packet + HEAD_SIZE;
```

Message를 출력하기 위해 계산하는 부분이다. HEAD_SIZE는 앞서 구한 Ethernet, IP, TCP 헤더 길이를 더한 것이다. 이것을 구하는 이유는 패킷이 헤더(Ethernet, IP, TCP)+Message로 구성되어 있기 때문이다.

payloadLength는 Message 길이를 저장하는데 전체 패킷 길이에서 앞서 구한 헤더 길이를 뺀 값이다.

payload의 경우 패킷에서 헤더를 건너뛰고 메세지가 시작되는 위치를 저장한 것이다.

```c
//print info
    	printf("----------------------------------------------------\n");
    	//MAC
    	printf("[Ethernet Header]\n");
    	printf(" Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
   	printf(" Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("\n");
	
    	//IP
    	printf("[IP Header]\n");
    	printf(" Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    	printf(" Dst IP: %s\n", inet_ntoa(ip->iph_destip));
	printf("\n");
	
    	//PORT
    	printf("[TCP Header]\n");
    	printf(" Src Port: %d\n", ntohs(tcp->tcp_sport));
    	printf(" Dst Port: %d\n", ntohs(tcp->tcp_dport));
	printf("\n");
	
    	//MESSAGE
    	printf("[Message info]\n");
    	int print_length = (payloadLength < 500) ? payloadLength : 500;

    	if (print_length > 0) printf("%.*s\n", print_length, payload);
 
    	printf("\n");
```

지금까지 구한 정보를 바탕으로 헤더에서 mac, ip, port 정보를 출력하고 message를 출력하는 부분이다.

message의 경우 전체를 다 출력하는 것이 아니다. 적당한 길이로 임의로 지정하여 출력하도록 하였다.

```c
printf("%.*s\n", print_length, payload);
```

message 출력시 이러한 방법을 사용하였는데 %.*s의 경우 %s는 문자열을 출력한다는 의미이고 .*의 경우 출력할 최대 문자수를 나타낸다. %.*s를 이용하기 위해서는 출력할 문자수와 출력할 문자열을 가리키는 포인터 두 가지 값이 필요하여 print_length, payload를 이용하였다.

# 3. 실행 결과

![image.png](attachment:4dad8340-ff0b-4c0c-91dc-2d50f1335f7f:image.png)

# 4. 전체 코드

```c
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
  int ipHeaderLength = 0;

// ethernet header 
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800)  // 0x0800 is IP type
  {
  //ip header
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    
    if(ip->iph_protocol == IPPROTO_TCP)// IPPROTO_TCP ??
    {
    	ipHeaderLength = ip->iph_ihl*4;
    	
    	//tcp header
    	struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader)+ipHeaderLength);
    	int tcpHeaderLength = TH_OFF(tcp)*4;
    	
    	// message
    	int HEAD_SIZE = sizeof(struct ethheader) + ipHeaderLength + tcpHeaderLength;
    	int payloadLength = header->len - HEAD_SIZE;
    	const u_char *payload = packet + HEAD_SIZE;
    	
	//print info
    	printf("----------------------------------------------------\n");
    	//MAC
    	printf("[Ethernet Header]\n");
    	printf(" Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
   	printf(" Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("\n");
	
    	//IP
    	printf("[IP Header]\n");
    	printf(" Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    	printf(" Dst IP: %s\n", inet_ntoa(ip->iph_destip));
	printf("\n");
	
    	//PORT
    	printf("[TCP Header]\n");
    	printf(" Src Port: %d\n", ntohs(tcp->tcp_sport));
    	printf(" Dst Port: %d\n", ntohs(tcp->tcp_dport));
	printf("\n");
	
    	//MESSAGE
    	printf("[Message info]\n");
    	int print_length = (payloadLength < 500) ? payloadLength : 500;

    	if (print_length > 0) printf("%.*s\n", print_length, payload);
 
    	printf("\n");
    	
    	
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

```
