/*���Ľ�����*/
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
    uint32_t sip;       //Դip
    uint32_t dip;       //Ŀ��ip
    uint16_t sport;     //Դport
    uint16_t dport;     //Ŀ��port
    uint8_t  proto;       //�����Э��PKT_IPPROTO_TCP��PKT_IPPROTO_UDP
    uint8_t *peth_pkt;      // ����ָ��
    uint8_t *pnet_pkt;      //�����ָ�룬�������ʼ
    uint8_t *ptrans_pkt;    //�����ָ�룬�������ʼ
    uint8_t *papp_pkt;      //���ݲ�ָ�룬���ݲ���ʼ
    uint8_t *pmpls_pkt;
	uint8_t *l2;
	uint8_t *l3;
	uint8_t *l4;
    uint16_t pkt_len;      //�������ĳ���
    uint16_t ethh_len;      //2-2.5��ͷ����
    uint16_t net_len;      //ip���ݳ��ȣ������+�����+Ӧ�ò�
    uint16_t trans_len;    //��������ݳ��ȣ������+Ӧ�ò�
    uint16_t app_len;      //Ӧ�ò����ݳ���
    uint16_t mpls_len;      //Ӧ�ò����ݳ���
    uint16_t eth_pack_num;   //2.5���װ����
    uint8_t  vlan_flag;
	uint8_t  ipfrag_flag;  //ip��Ƭ��ǣ�1��Ƭ
	uint8_t  mpls_flag;  
	uint8_t  ipv4_flag;
	uint8_t  ipv6_flag;
	uint8_t  icmp_flag;
	uint16_t app_proto; //Ӧ�ò�Э������
    PKT_TRANS_LAYER_U trans_info; //tcp,udp��Ϣ 
}PKT_INFO_S;
#pragma pack()

#define IP_SIP(p)		ntohl(((PKT_IP_HEADER_S *)(p))->saddr)			/*ԴIP*/
#define IP_DIP(p)		ntohl(((PKT_IP_HEADER_S *)(p))->daddr)			/*Ŀ��IP*/
#define IP_HLEN(p)		((((PKT_IP_HEADER_S *)(p))->ver_ihl & 0x0F) << 2)	/*IPͷ����*/
#define IP_PLEN(p)		ntohs(((PKT_IP_HEADER_S *)(p))->tlen)				/*IP������*/
#define IP_IDEN(p)      ntohs(((PKT_IP_HEADER_S *)(p))->identification)   /*IP����ʶ*/
#define IP_OFF(p)		((ntohs(((PKT_IP_HEADER_S *)(p))->flags_fo)&0x1FFF)<<3) 
#define IP_MF(p)		((((PKT_IP_HEADER_S *)(p))->flags_fo&0x20)>>5)		
#define UDP_SPORT(p)    ntohs(((PKT_UDP_HEADER_S *)(p))->sport)			/*Upd��Դ�˿�*/
#define UDP_DPORT(p)	ntohs(((PKT_UDP_HEADER_S *)(p))->dport)			/*Udp��Ŀ�Ķ˿�*/
#define UDP_PLEN(p)		ntohs(((PKT_UDP_HEADER_S *)(p))->len)				/*Udp���ĳ���*/
#define UDP_HLEN        (uint16_t)8
#define TCP_SN(p)		ntohl(((PKT_TCP_HEADER_S*)(p))->seq)
#define TCP_ACK(p)		ntohl(((PKT_TCP_HEADER_S*)(p))->ack)
#define TCP_HLEN(p)		((((PKT_TCP_HEADER_S*)(p))->flags&0x00F0)>>2)
#define TCP_SPORT(p)	ntohs(((PKT_TCP_HEADER_S *)(p))->sport)			/*Tcp��Դ�˿�*/
#define TCP_DPORT(p)    ntohs(((PKT_TCP_HEADER_S *)(p))->dport)			/*Tcp��Ŀ�Ķ˿�*/
#define TCP_WIN(p)      ntohs(((PKT_TCP_HEADER_S *)(p))->win)
#define TCP_SYN(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0200)
#define TCP_FIN(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0100)
#define TCP_RST(p)		(((PKT_TCP_HEADER_S*)(p))->flags&0x0400)
#define TCP_ACKF(p)      (((PKT_TCP_HEADER_S*)(p))->flags&0x1000)

/***************************************************************************
�������ģ���ȡ���ĵ�����㣬����㣬Ӧ�ò�������Ϣ
pkt_info:���Ļ����������ݽṹָ��, ����ʱӦ���peth_pkt��pkt_len��Ϣ�����ʱ��ýṹ����������Ϣ
****************************************************************************/
int pkt_get_hdr(PKT_INFO_S *ppkt_info);

#endif