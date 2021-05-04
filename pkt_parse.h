/*报文解析库*/
/*Init By Shawn.Z @ 20190812*/

#ifndef __PKT_PARSE_H__
#define __PKT_PARSE_H__

#include <inttypes.h>

#define PKT_PARSE_OK 0
#define PKT_PARSE_ERR -1

#define PKT_IPPROTO_ICMP                1       //ICMP
#define PKT_IPPROTO_TCP			  	    6		//TCP
#define PKT_IPPROTO_UDP					17		//UDP

#pragma pack(1)

typedef struct  {
	uint8_t		dest[6];
	uint8_t		src[6];
	uint16_t	type;
}PKT_ETH_HEADER_S;

///* IPv4 header */
typedef struct 
{
    uint8_t	ver_ihl;			/*Version (4 bits) + Internet header length (4 bits)*/
    uint8_t	tos;				/*Type of service*/
	uint16_t  tlen;				/*Total length*/ 
    uint16_t  identification;	/*Identification*/
    uint16_t  flags_fo;			/*Flags (3 bits) + Fragment offset (13 bits)*/
    uint8_t	ttl;				/*Time to live*/
    uint8_t	proto;				/*Protocol*/
    uint16_t  crc;				/*Header checksum*/
    uint32_t	saddr;			/*Source address*/
    uint32_t	daddr;			/*Destination address*/
    //uint32_t	op_pad;			/*Option + Padding*/
} PKT_IP_HEADER_S;
//
///* UDP header*/
typedef struct 
{
    uint16_t sport;				/*Source port*/
    uint16_t dport;				/*Destination port*/
    uint16_t len;					/*Datagram length*/
    uint16_t crc;					/*Checksum*/
} PKT_UDP_HEADER_S;
//
///* TCP header*/
typedef struct 
{
    uint16_t 	sport;				/*Source port*/
    uint16_t 	dport;				/*Destination port*/
    uint32_t	seq;				/*Sn number*/
    uint32_t	ack;				/*Ack number*/
    uint16_t	flags;
    uint16_t	win;				/*Window size*/
    uint16_t	sum;				/*Checksum*/
    uint16_t	urp;				/*Urgent pointer*/
} PKT_TCP_HEADER_S;

typedef struct 
{
    uint32_t          linkid;
    uint32_t          seq; //seq
    uint32_t		  ack;//ack
    uint32_t		  exp;//expire next seq
	uint16_t	      flags;
	uint16_t	      win;//Window size
	uint16_t	      crc;//Checksum
	uint16_t	      urp;//Urgent pointer
}PKT_TCP_S;

typedef struct 
{
    uint32_t      linkid;
	uint16_t      crc;	//Checksum
    uint32_t		len;    //udp len with head
    uint8_t*      data;
}PKT_UDP_S;

typedef union  
{
    PKT_TCP_S tcp;
    PKT_UDP_S udp;
}PKT_TRANS_LAYER_U;

typedef struct 
{
    uint32_t sip;       //源ip
    uint32_t dip;       //目的ip
    uint16_t sport;     //源port
    uint16_t dport;     //目的port
    uint8_t  proto;       //传输层协议PKT_IPPROTO_TCP，PKT_IPPROTO_UDP
    uint8_t *peth_pkt;      // 报文指针
    uint8_t *pnet_pkt;      //网络层指针，网络层起始
    uint8_t *ptrans_pkt;    //传输层指针，传输层起始
    uint8_t *papp_pkt;      //数据层指针，数据层起始
    uint8_t *pmpls_pkt;
	uint8_t *l2;
	uint8_t *l3;
	uint8_t *l4;
    uint16_t pkt_len;      //整个报文长度
    uint16_t ethh_len;      //2-2.5层头长度
    uint16_t net_len;      //ip数据长度，网络层+传输层+应用层
    uint16_t trans_len;    //传输层数据长度，传输层+应用层
    uint16_t app_len;      //应用层数据长度
    uint16_t mpls_len;      //应用层数据长度
    uint16_t eth_pack_num;   //2.5层封装层数
    uint8_t  vlan_flag;
	uint8_t  ipfrag_flag;  //ip分片标记，1分片
	uint8_t  mpls_flag;  
	uint8_t  ipv4_flag;
	uint8_t  ipv6_flag;
	uint8_t  icmp_flag;
	uint16_t app_proto; //应用层协议类型
    PKT_TRANS_LAYER_U trans_info; //tcp,udp信息 
}PKT_INFO_S;
#pragma pack()

#define IP_SIP(p)		ntohl(((PKT_IP_HEADER_S *)(p))->saddr)			/*源IP*/
#define IP_DIP(p)		ntohl(((PKT_IP_HEADER_S *)(p))->daddr)			/*目的IP*/
#define IP_HLEN(p)		((((PKT_IP_HEADER_S *)(p))->ver_ihl & 0x0F) << 2)	/*IP头长度*/
#define IP_PLEN(p)		ntohs(((PKT_IP_HEADER_S *)(p))->tlen)				/*IP包长度*/
#define IP_IDEN(p)      ntohs(((PKT_IP_HEADER_S *)(p))->identification)   /*IP包标识*/
#define IP_OFF(p)		((ntohs(((PKT_IP_HEADER_S *)(p))->flags_fo)&0x1FFF)<<3) 
#define IP_MF(p)		((((PKT_IP_HEADER_S *)(p))->flags_fo&0x20)>>5)		
#define UDP_SPORT(p)    ntohs(((PKT_UDP_HEADER_S *)(p))->sport)			/*Upd包源端口*/
#define UDP_DPORT(p)	ntohs(((PKT_UDP_HEADER_S *)(p))->dport)			/*Udp包目的端口*/
#define UDP_PLEN(p)		ntohs(((PKT_UDP_HEADER_S *)(p))->len)				/*Udp包的长度*/
#define UDP_HLEN        (uint16_t)8
#define TCP_SN(p)		ntohl(((PKT_TCP_HEADER_S*)(p))->seq)
#define TCP_ACK(p)		ntohl(((PKT_TCP_HEADER_S*)(p))->ack)
#define TCP_HLEN(p)		((((PKT_TCP_HEADER_S*)(p))->flags&0x00F0)>>2)
#define TCP_SPORT(p)	ntohs(((PKT_TCP_HEADER_S *)(p))->sport)			/*Tcp包源端口*/
#define TCP_DPORT(p)    ntohs(((PKT_TCP_HEADER_S *)(p))->dport)			/*Tcp包目的端口*/
#define TCP_WIN(p)      ntohs(((PKT_TCP_HEADER_S *)(p))->win)
#define TCP_SYN(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0200)
#define TCP_FIN(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0100)
#define TCP_RST(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0400)
#define TCP_ACKF(p)      (((PKT_TCP_HEADER_S*)(p))->flags&0x1000)

/***************************************************************************
分析报文，获取报文的网络层，传输层，应用层数据信息
pkt_info:报文基本控制数据结构指针, 输入时应填好peth_pkt，pkt_len信息，输出时填好结构体内其它信息
****************************************************************************/
int pkt_get_hdr(PKT_INFO_S *ppkt_info);

#endif