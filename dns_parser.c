#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <stdint.h>

#include "dns_parser.h"

int dns_parse(char* dns_pkt, unsigned short dns_pkt_len, DNS_REQUEST_INFO* dns_req)
{   
    char  DNSNAME[256] = {0};
    int i            = 0;
    int n            = 0;
    int ret          = 0;
    int len          = 0;
    unsigned short pkt_offset   = 0;
    char *dnsname_end = NULL;
    char *pdata       = NULL;

    char *pPktEnd     = dns_pkt + dns_pkt_len;
    pdata = dns_pkt;        
    dns_req->requestID = ntohs((*(unsigned short*)pdata));
    dns_req->requestFlag =ntohs((*(unsigned short*)(pdata+2)));

    //查找到dnsname 结束
    pkt_offset += DNS_DATA_OFFSET;
    dnsname_end =  memchr(pdata+pkt_offset, 0x00, dns_pkt_len-pkt_offset);
    if (NULL == dnsname_end)
    {
        return -1;
    }

    unsigned short dnsname_len = dnsname_end - (pdata + pkt_offset);
    if (dnsname_len >= DNS_MAX_NAME_LEN)
    {
        return -1;
    }

    dns_req->dns_queries_data = pdata + pkt_offset;
    dns_req->dns_queries_len = dnsname_len + 5;

    while((pdata + pkt_offset) < (dnsname_end-1))  //DNS名称提取
    {
        if (0 < i)
        {
            //为上一个域名段填充' . '
            DNSNAME[i] = DNS_DOT;   
            pkt_offset += 1;
        }
            
        len =*(unsigned char*)(pdata+pkt_offset);
        if (len >= dns_pkt_len - pkt_offset)
        {
            //若计算的长度大于剩余长度，异常!
            return -1;
        }

        if (n+len > DNS_DATA_LENGTH)
        {
            break;
        }

        for(i=n;i<(n+len);i++)
        {
            pkt_offset += 1;
            DNSNAME[i]=*(unsigned char *)(pdata+pkt_offset);
        }
        
        n += (len+1);//n记录当前域名解析的偏移    
    }

    int domain_len = strlen(DNSNAME);
    memcpy(dns_req->DNSname, &DNSNAME, domain_len);
    dns_req->DNSname[domain_len] = 0;
    
    //Check if the pkt valid
    if (dnsname_end+4 > pPktEnd)
    {
        return -1;
    }
    
    dns_req->requestType = ntohs(*(unsigned short*)(dnsname_end + 1));
    dns_req->requestClass = ntohs(*(unsigned short*)(dnsname_end + 3));

    return 0;
}

