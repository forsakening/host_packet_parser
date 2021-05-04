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

/*֧�ֵ�2�㸺��Э������*/
#define PKT_ETHER_MPLS_UNI_TYPE			0x8847	//����
#define PKT_ETHER_MPLS_MULTI_TYPE		0x8848	//�ಥ
#define PKT_ETHER_MACINMAC_TYPE			0x88A8	// macinmac 
#define PKT_ETHER_IP_TYPE				0x0800  // IP
#define PKT_ETHER_IPV6_TYPE                     0x86dd
#define PKT_ETHER_8021Q_TYPE			0x8100	// 802.1Q VLAN 
#define PKT_ETHER_QINQ_TYPE				0x9100	// QinQ VLAN
#define PKT_ETHER_PPPOED_TYPE			0x8863	// PPPoE ����Э�� 
#define PKT_ETHER_PPPOES_TYPE			0x8864	// PPPoE�ỰЭ�� 
#define PKT_ETHER_UNKNOWN_TYPE			0xFFFF	//δ֪

//ʶ��PPPoEͷ����
#define PKT_PPPOE_IP_TYPE					0x0021		// ip
#define PKT_PPPOE_MPLS_UNI_TYPE				0x0281		// mpls unicast
#define PKT_PPPOE_MPLS_MULTI_TYPE			0x0283		// mpls multicast

#define PKT_VLAN_MAX_LAYER_NUM			2		//VLAN���Ƕ�ײ���
#define PKT_MPLS_MAX_LAYER_NUM			10		//MPLS���Ƕ�ײ���
#define PKT_ETH_HLEN				    14		//��̫��ͷ����

//GRE������- ��ѭRFC2784 
#define GRE_IP_PROTO_TYPE				47		//GREһ���װ��IP�У�IP.proto=47 ��ʾGRE
#define GRE_PROTO_IP					0x0800
#define GRE_PROTO_PPP					0x880b

//PPPЭ�����
#define PPP_PROTO_IP					0x0021
/***************************************************************************
*                                 struct
****************************************************************************/
#pragma pack(1)

///MPLSͷ
typedef struct _pkt_mpls_hdr_s
{
    uint8_t			l0;		//label 0
    uint8_t			l1;		//label 1
    uint8_t			s:1,	//1Ϊջ��
           			cos:3,	//class of service
           			l2:4;	//label 2
    uint8_t			ttl;	//time to live
}PKT_MPLS_HEADER_S;

/// VLANͷ
typedef struct _pkt_vlan_hdr_s
{
    uint16_t		vlan_tag;			//��ǩ,0x8100:802.1Q,0x9100:QiniQ
    uint16_t		vlan_type;			//��������
}PKT_VLAN_HEADER_S;

typedef struct _pkt_pppoe_hdr_s
{
    uint8_t			ver_type;		// 4λ�汾+4λ����
    uint8_t			code;		    //������
    uint16_t		    sess_id;	    //�ỰID
    uint16_t		    len;			//���س���
	uint16_t		    payload_type;	//PPP��������
}PKT_PPPOE_HEADER_S;

//RFC2784 / RFC1701 GRE ͷ��
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
����VLANͷ
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
����mplsͷ
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
�������ģ���ȡ���ĵ�����㣬����㣬Ӧ�ò�������Ϣ
pkt_info:���Ļ����������ݽṹָ��, ����ʱӦ���peth_pkt��pktlen��Ϣ�����ʱ��ýṹ����������Ϣ
�����ɹ�����PKT_PARSE_OK
����ʧ�ܷ���PKT_PARSE_ERR
��Ƭ�Ļ����������������
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
����ethͷ��ȡ�����ָ��
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
			
			    ppkt_info->mpls_flag = 1; //mpls��
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
��������ͷ��ȡ�����ָ��
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

    //����㳤��,ȡIPͷ�еĳ���
    ppkt_info->net_len = ipp_len;
    ppkt_info->sip = IP_SIP(pip_hdr);
    ppkt_info->dip = IP_DIP(pip_hdr);
    ppkt_info->proto = pip_hdr->proto;
    ppkt_info->ptrans_pkt = ppkt_info->pnet_pkt + iph_len;
    ppkt_info->trans_len = ppkt_info->net_len - iph_len;

	if(pkt_chk_frag((uint8_t *)pip_hdr)==PKT_PARSE_OK)
	{
		ppkt_info->ipfrag_flag= 1;//��Ƭ
	}
	else
	{
		ppkt_info->ipfrag_flag=0;
	}

	ppkt_info->l3 = ppkt_info->pnet_pkt;
    return PKT_PARSE_OK;
}

/**************************************************************************
��������ͷ��ȡӦ�ò�ָ��
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

