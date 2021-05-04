#include <stdio.h>

#include "ssl_parser.h"
#include "pkt_parse.h"
#include "dns_parser.h"
#include "http_parser.h"

void CallBackPacket(char *data, int len)
{
    PKT_INFO_S pkt_info = {0};
    pkt_info.pkt_len = len;
    pkt_info.peth_pkt = data;
    int err = pkt_get_hdr(&pkt_info);
    if (err != PKT_PARSE_OK)
    {
        //printf("Parse Error \n");
        return;
    }

    if (pkt_info.proto == PKT_IPPROTO_TCP && pkt_info.dport == 443)
    {
        //printf("-------------Https Packet Start------------- \n");

        char servername[128] = {0};
        int namelen = 0;
        err = ssl_clienthello_parser_servername(pkt_info.papp_pkt, pkt_info.app_len, servername, &namelen);
        if (err != 0)
        {
            //printf("    Not Find ServerName.\n");
        }
        else
        {
            if (namelen >= 128)
                return;

            servername[namelen] = 0;
            printf("[HTTPS] Find ServerName: %s, Sip:%d.%d.%d.%d Dip:%d.%d.%d.%d Sport:%d Dport:%d \n", servername,
                pkt_info.sip >> 24 & 0xff, pkt_info.sip >> 16 & 0xff, pkt_info.sip >> 8 & 0xff, pkt_info.sip & 0xff,
                pkt_info.dip>> 24 & 0xff, pkt_info.dip >> 16 & 0xff, pkt_info.dip >> 8 & 0xff, pkt_info.dip & 0xff,
                pkt_info.sport, pkt_info.dport);
        }
        
        //printf("-------------Https Packet E n d------------- \n");
    }
    else if (pkt_info.proto == PKT_IPPROTO_UDP && pkt_info.dport == 53)
    {
        DNS_REQUEST_INFO dns_req = {0};
        err = dns_parse(pkt_info.papp_pkt, pkt_info.app_len, &dns_req);
        if (err == 0)
        {
            printf("[DNS] DNS ServerName: %s, Sip:%d.%d.%d.%d Dip:%d.%d.%d.%d Sport:%d Dport:%d \n", dns_req.DNSname,
                pkt_info.sip >> 24 & 0xff, pkt_info.sip >> 16 & 0xff, pkt_info.sip >> 8 & 0xff, pkt_info.sip & 0xff,
                pkt_info.dip>> 24 & 0xff, pkt_info.dip >> 16 & 0xff, pkt_info.dip >> 8 & 0xff, pkt_info.dip & 0xff,
                pkt_info.sport, pkt_info.dport);
        }
       
    }
    else if (pkt_info.proto == PKT_IPPROTO_TCP && pkt_info.dport == 80)
    {
        struct http_message http_msg = {0};
        err = http_parser(pkt_info.papp_pkt, &http_msg, HTTP_REQUEST);
        if (err == 0)
        {
            int i = 0;
            char host[256] = {0};
            for (; i < 16; i++)
            {
                if (http_msg.headers[i].name)
                {
                    if (strncmp(http_msg.headers[i].name, "Host", 4) == 0)
                    {
                        strcpy(host, http_msg.headers[i].value);
                        int len = strlen(host);
                        if (host[len-1] == '\r')
                            host[len-1] = 0;
                        break;
                    }
                }
            }

            printf("[HTTP] Method:%s Host:%s URL: %s, Sip:%d.%d.%d.%d Dip:%d.%d.%d.%d Sport:%d Dport:%d \n", 
                http_msg.method,
                host,
                http_msg.url,
                pkt_info.sip >> 24 & 0xff, pkt_info.sip >> 16 & 0xff, pkt_info.sip >> 8 & 0xff, pkt_info.sip & 0xff,
                pkt_info.dip>> 24 & 0xff, pkt_info.dip >> 16 & 0xff, pkt_info.dip >> 8 & 0xff, pkt_info.dip & 0xff,
                pkt_info.sport, pkt_info.dport);            
        }
    }

    return;
}

