//@20180413 by Shawn.Z 
//Ethernet Packet Parser
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "pkt_parse.h"

/****************************************************************************
*  macro
*****************************************************************************/

/*支持的2层负载协议类型*/
#define PKT_ETHER_MPLS_UNI_TYPE			0x8847	//单播
#define PKT_ETHER_MPLS_MULTI_TYPE		0x8848	//多播
#define PKT_ETHER_MACINMAC_TYPE			0x88A8	// macinmac 
#define PKT_ETHER_IP_TYPE				0x0800  // IP
#define PKT_ETHER_IPV6_TYPE                     0x86dd
#define PKT_ETHER_8021Q_TYPE			0x8100	// 802.1Q VLAN 
#define PKT_ETHER_QINQ_TYPE				0x9100	// QinQ VLAN
#define PKT_ETHER_PPPOED_TYPE			0x8863	// PPPoE 发现协议 
#define PKT_ETHER_PPPOES_TYPE			0x8864	// PPPoE会话协议 
#define PKT_ETHER_UNKNOWN_TYPE			0xFFFF	//未知

//识别PPPoE头类型
#define PKT_PPPOE_IP_TYPE					0x0021		// ip
#define PKT_PPPOE_MPLS_UNI_TYPE				0x0281		// mpls unicast
#define PKT_PPPOE_MPLS_MULTI_TYPE			0x0283		// mpls multicast

#define PKT_VLAN_MAX_LAYER_NUM			2		//VLAN最大嵌套层数
#define PKT_MPLS_MAX_LAYER_NUM			10		//MPLS最大嵌套层数
#define PKT_ETH_HLEN				    14		//以太网头长度

//GRE隧道相关- 遵循RFC2784 
#define GRE_IP_PROTO_TYPE				47		//GRE一般封装在IP中，IP.proto=47 表示GRE
#define GRE_PROTO_IP					0x0800
#define GRE_PROTO_PPP					0x880b

//PPP协议相关
#define PPP_PROTO_IP					0x0021
/***************************************************************************
*                                 struct
****************************************************************************/
#pragma pack(1)

///MPLS头
typedef struct _pkt_mpls_hdr_s
{
    uint8_t			l0;		//label 0
    uint8_t			l1;		//label 1
    uint8_t			s:1,	//1为栈底
           			cos:3,	//class of service
           			l2:4;	//label 2
    uint8_t			ttl;	//time to live
}PKT_MPLS_HEADER_S;

/// VLAN头
typedef struct _pkt_vlan_hdr_s
{
    uint16_t		vlan_tag;			//标签,0x8100:802.1Q,0x9100:QiniQ
    uint16_t		vlan_type;			//负载类型
}PKT_VLAN_HEADER_S;

typedef struct _pkt_pppoe_hdr_s
{
    uint8_t			ver_type;		// 4位版本+4位类型
    uint8_t			code;		    //代码域
    uint16_t		    sess_id;	    //会话ID
    uint16_t		    len;			//负载长度
	uint16_t		    payload_type;	//PPP负载类型
}PKT_PPPOE_HEADER_S;

//RFC2784 / RFC1701 GRE 头部
typedef struct
{
	/* must */
	uint16_t head_flag;
	uint16_t prototype;
	/* optional */
}GRE_HEADER_S;

typedef struct
{
	uint8_t C:1;
	uint8_t R:1;
	uint8_t K:1;
	uint8_t S:1;
	uint8_t s:1;
	uint8_t Recur:3;
	uint8_t A:1;
	uint8_t Flags:4;
	uint8_t ver:3;
}GRE_HEAD_FLAG_S;

#define GRE_HEAD_C(head_flag) (head_flag >> 15 & 0b1)
#define GRE_HEAD_R(head_flag) (head_flag >> 14 & 0b1)
#define GRE_HEAD_K(head_flag) (head_flag >> 13 & 0b1)
#define GRE_HEAD_S(head_flag) (head_flag >> 12 & 0b1)
#define GRE_HEAD_s(head_flag) (head_flag >> 11 & 0b1)
#define GRE_HEAD_Recur(head_flag) (head_flag >> 8  & 0b111)
#define GRE_HEAD_A(head_flag) (head_flag >> 7  & 0b1)
#define GRE_HEAD_F(head_flag) (head_flag >> 3  & 0b1111)
#define GRE_HEAD_V(head_flag) (head_flag >> 0  & 0b111)

#pragma pack()
    
/***************************************************************************
*                        function declare   
****************************************************************************/
int pkt_parse_ethhdr(PKT_INFO_S *ppkt_info);
int pkt_parse_nethdr(PKT_INFO_S *ppkt_info);
int pkt_parse_transhdr(PKT_INFO_S *ppkt_info);
static int pkt_parse_vlan(uint8_t *ppkt, uint16_t pktlen, short *ptype, short *ppack_num);
static int pkt_parse_mpls(uint8_t *ppkt, uint16_t pktlen, short *ptype, short *ppack_num);


/**************************************************************************
解析VLAN头
***************************************************************************/
static int pkt_parse_vlan(uint8_t *ppkt, uint16_t pktlen, short *ptype, short *ppack_num)
{
    int  i         = 0;
    uint16_t vlan_type = 0;
    int  hdr_len   = 0;

    if (NULL == ppkt || 0 == pktlen || NULL == ptype || NULL == ppack_num)
        return PKT_PARSE_ERR;

    *ptype = (short)PKT_ETHER_UNKNOWN_TYPE;
	for(i=0;i<PKT_VLAN_MAX_LAYER_NUM;i++)
	{
		if(pktlen > sizeof(PKT_VLAN_HEADER_S))
		{
			(*ppack_num)++;
			hdr_len += sizeof(PKT_VLAN_HEADER_S);
			vlan_type = ntohs(((PKT_VLAN_HEADER_S *)ppkt)->vlan_type);

			if (PKT_ETHER_8021Q_TYPE != vlan_type && PKT_ETHER_QINQ_TYPE != vlan_type)
			{
				*ptype = vlan_type;
				break;
			}

			ppkt += sizeof(PKT_VLAN_HEADER_S);
			pktlen -= sizeof(PKT_VLAN_HEADER_S);
		
		}
		else
			break;	
	}

    return hdr_len;
}

/**************************************************************************
解析mpls头
***************************************************************************/
static int pkt_parse_mpls(uint8_t *ppkt, uint16_t pktlen, short *ptype, short *ppack_num)
{
    int              i         = 0;
    PKT_MPLS_HEADER_S *pmpls_hdr = NULL;
    int              hdr_len   = 0;

    if (NULL == ppkt || 0 == pktlen || NULL == ptype || NULL == ppack_num)
        return PKT_PARSE_ERR;

    *ptype = (short)PKT_ETHER_UNKNOWN_TYPE;
	for(i=0;i<PKT_MPLS_MAX_LAYER_NUM;i++)
	{
		if(pktlen > sizeof(PKT_MPLS_HEADER_S))
		{
		    (*ppack_num)++;
			hdr_len += sizeof(PKT_MPLS_HEADER_S);
			pmpls_hdr = (PKT_MPLS_HEADER_S *)ppkt;
			if(1==pmpls_hdr->s)
			{
				*ptype = PKT_ETHER_IP_TYPE;
				break;
			}

			ppkt += sizeof(PKT_MPLS_HEADER_S);
			pktlen -= sizeof(PKT_MPLS_HEADER_S);		
		}
		else
			break;
	}

    return hdr_len;
}

/**************************************************************************
分析报文，获取报文的网络层，传输层，应用层数据信息
pkt_info:报文基本控制数据结构指针, 输入时应填好peth_pkt，pktlen信息，输出时填好结构体内其它信息
分析成功返回PKT_PARSE_OK
分析失败返回PKT_PARSE_ERR
分片的话不分析传输层数据
***************************************************************************/
int pkt_get_hdr(PKT_INFO_S *ppkt_info)
{
	if (NULL == ppkt_info || NULL == ppkt_info->peth_pkt || PKT_ETH_HLEN >= ppkt_info->pkt_len)
        return PKT_PARSE_ERR;

	ppkt_info->l2 = NULL;
	ppkt_info->l3 = NULL;
	ppkt_info->l4 = NULL;
	ppkt_info->ipfrag_flag = 0;
	ppkt_info->mpls_flag = 0;
	ppkt_info->vlan_flag = 0;
	ppkt_info->ipv4_flag = 0;
    ppkt_info->ipv6_flag = 0;
	ppkt_info->icmp_flag = 0;
	ppkt_info->proto = 0;

	if(pkt_parse_ethhdr(ppkt_info)==PKT_PARSE_ERR)
		return PKT_PARSE_ERR;

	//@20180730 support ipv6
	if (ppkt_info->ipv6_flag)
		return PKT_PARSE_OK;

	if(pkt_parse_nethdr(ppkt_info)==PKT_PARSE_ERR)
		return PKT_PARSE_ERR;
	if(1==ppkt_info->ipfrag_flag)
		return PKT_PARSE_OK;
	if(pkt_parse_transhdr(ppkt_info)==PKT_PARSE_ERR)
		return PKT_PARSE_ERR;

	return PKT_PARSE_OK;

}

/**************************************************************************
分析eth头，取网络层指针
***************************************************************************/
int pkt_parse_ethhdr(PKT_INFO_S *ppkt_info)
{
    int   eth_hdr_len  = 0;
    short   eth_pack_num = 1;
    char    flag_parse   = 0;
    uint8_t   *ppkt        = NULL;
    uint16_t  pktlen       = 0;
    uint16_t  eth_type     = 0;
    
    if (NULL == ppkt_info || PKT_ETH_HLEN >= ppkt_info->pkt_len|| NULL == ppkt_info->peth_pkt )
        return PKT_PARSE_ERR;

    ppkt        = ppkt_info->peth_pkt;
	pktlen     = ppkt_info->pkt_len;
	ppkt_info->l2 = ppkt;
    eth_type    = ntohs(*((uint16_t*)(ppkt+12)));
    eth_hdr_len = PKT_ETH_HLEN;	
    if(pktlen <= eth_hdr_len)	
        return PKT_PARSE_ERR;

    ppkt    += eth_hdr_len;	
    pktlen -= eth_hdr_len;

	flag_parse = 0;
	while (1 != flag_parse && pktlen> 0)
	{
		switch(eth_type)
		{
			case PKT_ETHER_IP_TYPE:
				flag_parse = 1;
				break;

			case PKT_ETHER_IPV6_TYPE:
				ppkt_info->ipv6_flag = 1;
				flag_parse = 1;
				break; 

			case PKT_ETHER_8021Q_TYPE:
			case PKT_ETHER_QINQ_TYPE:
				eth_hdr_len = pkt_parse_vlan(ppkt, pktlen, (short *)&eth_type, &eth_pack_num);
				if(PKT_PARSE_ERR==eth_hdr_len )
					return PKT_PARSE_ERR;
				ppkt += eth_hdr_len;
				pktlen -= eth_hdr_len;
				ppkt_info->vlan_flag = 1;
				break;

			case PKT_ETHER_MPLS_UNI_TYPE:
			case PKT_ETHER_MPLS_MULTI_TYPE:
			
			    ppkt_info->mpls_flag = 1; //mpls包
		        ppkt_info->pmpls_pkt = ppkt;
		        ppkt_info->mpls_len = pktlen;
		        
				eth_hdr_len = pkt_parse_mpls(ppkt, pktlen, (short *)&eth_type, &eth_pack_num);
				if(PKT_PARSE_ERR==eth_hdr_len)
					return PKT_PARSE_ERR;
				ppkt += eth_hdr_len;
				pktlen -= eth_hdr_len;
				break;
				
			default:
				//unsupport ether type
				return PKT_PARSE_ERR;
		}
	}
    ppkt_info->pnet_pkt = ppkt;
    ppkt_info->net_len  = pktlen;
    ppkt_info->ethh_len  = ppkt_info->pkt_len - ppkt_info->net_len;
    ppkt_info->eth_pack_num = eth_pack_num;

    return PKT_PARSE_OK;
}

static int pkt_chk_frag(uint8_t *pip_pkt)
{
	if(0 != IP_MF(pip_pkt) || 0 != IP_OFF(pip_pkt))
		return PKT_PARSE_OK;
	return PKT_PARSE_ERR;
}
/**************************************************************************
分析网络头，取传输层指针
***************************************************************************/
int pkt_parse_nethdr(PKT_INFO_S *ppkt_info)
{
    int     iph_len  = 0;
    int     ipp_len  = 0;
    PKT_IP_HEADER_S *pip_hdr  = NULL;

    if (NULL == ppkt_info || sizeof(PKT_IP_HEADER_S) >= ppkt_info->net_len || NULL == ppkt_info->pnet_pkt)
        return PKT_PARSE_ERR;

	pip_hdr = (PKT_IP_HEADER_S *)ppkt_info->pnet_pkt;
    ipp_len = IP_PLEN(pip_hdr);
    iph_len = IP_HLEN(pip_hdr);
    if ((0x40 != (pip_hdr->ver_ihl&0xf0)) || (0 != (iph_len&0x03)) || (int)sizeof(PKT_IP_HEADER_S) > iph_len+4 || iph_len > ipp_len || ipp_len > (int)ppkt_info->net_len)
        return PKT_PARSE_ERR; //unsupported net protocol or error packet

	ppkt_info->ipv4_flag = 1;

    //网络层长度,取IP头中的长度
    ppkt_info->net_len = ipp_len;
    ppkt_info->sip = IP_SIP(pip_hdr);
    ppkt_info->dip = IP_DIP(pip_hdr);
    ppkt_info->proto = pip_hdr->proto;
    ppkt_info->ptrans_pkt = ppkt_info->pnet_pkt + iph_len;
    ppkt_info->trans_len = ppkt_info->net_len - iph_len;

	if(pkt_chk_frag((uint8_t *)pip_hdr)==PKT_PARSE_OK)
	{
		ppkt_info->ipfrag_flag= 1;//分片
	}
	else
	{
		ppkt_info->ipfrag_flag=0;
	}

	ppkt_info->l3 = ppkt_info->pnet_pkt;
    return PKT_PARSE_OK;
}

/**************************************************************************
分析传输头，取应用层指针
***************************************************************************/
int pkt_parse_transhdr(PKT_INFO_S *ppkt_info)
{

    PKT_TCP_HEADER_S *ptcp_hdr   = NULL;
    int      tcph_len   = 0;
    PKT_UDP_HEADER_S *pudp_hdr   = NULL;
    int udpp_len        = 0;

    if (NULL == ppkt_info || NULL == ppkt_info->ptrans_pkt)
        return PKT_PARSE_ERR;

	switch(ppkt_info->proto)
	{
		case PKT_IPPROTO_UDP:
	        if (sizeof(PKT_UDP_HEADER_S) > ppkt_info->trans_len)
				goto __trans_hdr_err;

	        pudp_hdr = (PKT_UDP_HEADER_S *)ppkt_info->ptrans_pkt;
	        udpp_len = UDP_PLEN(pudp_hdr);
	        if (udpp_len != ppkt_info->trans_len)
				goto __trans_hdr_err;

	        ppkt_info->sport = UDP_SPORT(pudp_hdr);
	        ppkt_info->dport = UDP_DPORT(pudp_hdr);
	        ppkt_info->papp_pkt = ppkt_info->ptrans_pkt + UDP_HLEN;
	        ppkt_info->app_len = ppkt_info->trans_len - UDP_HLEN;
			ppkt_info->trans_info.udp.crc=pudp_hdr->crc;
			ppkt_info->trans_info.udp.len=pudp_hdr->len;

			break;
		case PKT_IPPROTO_TCP:
			if (sizeof(PKT_TCP_HEADER_S) > ppkt_info->trans_len)
				goto __trans_hdr_err;

	        ptcp_hdr = (PKT_TCP_HEADER_S *)ppkt_info->ptrans_pkt;
	        tcph_len = TCP_HLEN(ptcp_hdr);
	        if ((int)sizeof(PKT_TCP_HEADER_S) > tcph_len || (0 != (tcph_len&0x03)) || tcph_len > (int)ppkt_info->trans_len)
				goto __trans_hdr_err;

	        ppkt_info->sport = TCP_SPORT(ptcp_hdr);
	        ppkt_info->dport = TCP_DPORT(ptcp_hdr);
	        ppkt_info->papp_pkt = ppkt_info->ptrans_pkt + tcph_len;
	        ppkt_info->app_len = ppkt_info->trans_len - tcph_len;
			ppkt_info->trans_info.tcp.seq=ptcp_hdr->seq;
			ppkt_info->trans_info.tcp.ack=ptcp_hdr->ack;
			ppkt_info->trans_info.tcp.flags=ptcp_hdr->flags;
			ppkt_info->trans_info.tcp.win=ptcp_hdr->win;
			ppkt_info->trans_info.tcp.crc=ptcp_hdr->sum;
			ppkt_info->trans_info.tcp.urp=ptcp_hdr->urp;
			break;
		case PKT_IPPROTO_ICMP:
			ppkt_info->icmp_flag = 1;
			break;
		default:
			 //unsupported trans protocol
	        return PKT_PARSE_ERR;

	}

	ppkt_info->l4 = ppkt_info->ptrans_pkt;
    return PKT_PARSE_OK;

__trans_hdr_err:
        return PKT_PARSE_ERR;
}

