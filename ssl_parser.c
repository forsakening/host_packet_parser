#include <stdio.h>
#include <arpa/inet.h>

#include "ssl_parser.h"

#define SSL_PACKET_HANDSHAKE 0x16
#define SSL_PACKET_TLS_1_0   0x0301
#define SSL_PACKET_TLS_1_1   0x0302
#define SSL_PACKET_TLS_1_2   0x0303
#define SSL_PACKET_CLIENT_HELLO 0x01

//#define SSL_DEBUG(fmt,...)  printf("[File:"__FILE__", Line:%d]  "fmt"\n", __LINE__, ##__VA_ARGS__)
#define SSL_DEBUG(fmt,...)

int ssl_clienthello_parser_servername(unsigned char* ssl_buf, 
                                                     unsigned int ssl_len, 
                                                     unsigned char* server_name, 
                                                     unsigned int* servername_len)
{
    if (ssl_len <= 43)
    {
        SSL_DEBUG("ssl_len %d error!", ssl_len);
        return -1;
    }

    int left_len = ssl_len;
    unsigned char *p_sslbuf = ssl_buf;
    unsigned char ssl_content_type = p_sslbuf[0];
    if (ssl_content_type != SSL_PACKET_HANDSHAKE)
    {
        return -1;
    }    
    p_sslbuf += 1;   

    unsigned short ssl_version = ntohs(*(unsigned short*)p_sslbuf);
    if (ssl_version != SSL_PACKET_TLS_1_0 && ssl_version != SSL_PACKET_TLS_1_1 && ssl_version != SSL_PACKET_TLS_1_2)
    {
        SSL_DEBUG("ssl_version %d error!", ssl_version);
        return -1;
    }
    p_sslbuf += 2;

    unsigned short ssl_length = ntohs(*(unsigned short*)p_sslbuf);
    if ((ssl_length + 5) != ssl_len)
    {
        SSL_DEBUG("ssl_length %d + 5 != ssl_len %d!", ssl_length, ssl_len);
        return -1;
    }
    p_sslbuf += 2;
    
    unsigned char handshake_type = p_sslbuf[0];
    if (handshake_type != SSL_PACKET_CLIENT_HELLO)
    {
        return -1;
    }
    p_sslbuf += 1;

    unsigned short handshake_length = (p_sslbuf[0] << 16) +  (p_sslbuf[1] << 8) + p_sslbuf[2];
    if (handshake_length != (ssl_length - 4))
    {
        SSL_DEBUG("handshake_length %d != ssl_length %d - 4! %d-%d-%d", handshake_length, ssl_length, p_sslbuf[0],p_sslbuf[1],p_sslbuf[2]);
        return -1;
    }
    p_sslbuf += 3;

    unsigned short handshake_version = ntohs(*(unsigned short*)p_sslbuf);
    if (handshake_version != SSL_PACKET_TLS_1_0 && handshake_version != SSL_PACKET_TLS_1_1 && handshake_version != SSL_PACKET_TLS_1_2)
    {
        SSL_DEBUG("handshake_version %d error!", handshake_version);
        return -1;
    }
    p_sslbuf += 2;

    //skip randome, 32 bytes
    p_sslbuf += 32;
    left_len = ssl_len - 43;// 43 = 5 + 6 + 32
    
    //session ID
    unsigned char session_len = p_sslbuf[0];
    left_len -= 1;
    if (session_len >= left_len) 
    {
        SSL_DEBUG("session_len %d error,left_len:%d !", session_len, left_len);
        return -1;
    }
    p_sslbuf += 1;
    p_sslbuf += session_len;
    left_len -= session_len;

    //CipherSuiteList
    unsigned short cipher_suite_len = ntohs(*(unsigned short*)p_sslbuf);
    p_sslbuf += 2;
    left_len -= 2;
    if (cipher_suite_len >= left_len)
    {
        SSL_DEBUG("cipher_suite_len %d error,left_len:%d !", cipher_suite_len, left_len);
        return -1;
    }
    p_sslbuf += cipher_suite_len;
    left_len -= cipher_suite_len;

    //CompressionMethod
    unsigned char compression_len = p_sslbuf[0];
    left_len -= 1;
    p_sslbuf += 1;
    if (compression_len >= left_len) 
    {
        SSL_DEBUG("compression_len %d error,left_len:%d !", compression_len, left_len);
        return -1;
    }
    p_sslbuf += compression_len;
    left_len -= compression_len;

    //Extension
    unsigned short extension_len = ntohs(*(unsigned short*)p_sslbuf);
    p_sslbuf += 2;
    left_len -= 2;
    if (extension_len > left_len)
    {
        SSL_DEBUG("extension_len %d error,left_len:%d !", extension_len, left_len);
        return -1;
    }

    //loop extension, type(2 bytes) + len(2 bytes)
    unsigned char find_server_name = 0;
    unsigned short ext_type, ext_len;
    while (left_len > 4)
    {
        ext_type = ntohs(*(unsigned short*)p_sslbuf);
        ext_len  = ntohs(*(unsigned short*)(p_sslbuf + 2));
        p_sslbuf += 4;
        left_len -= 4;

        if (ext_len > left_len)
        {
            SSL_DEBUG("ext_len %d error,left_len:%d !", ext_len, left_len);
            return -1;
        }

        //resolve extension server name
        if (ext_type == 0x0)
        {
            unsigned char* p_namebuf = p_sslbuf;
            int name_leftlen = ext_len;
            unsigned short name_listlen = ntohs(*(unsigned short*)p_namebuf);
            unsigned char name_type = p_namebuf[1];
            p_namebuf += 3;
            name_leftlen -= 3;
            
            unsigned short name_len = ntohs(*(unsigned short*)p_namebuf);
            p_namebuf += 2;
            name_leftlen -= 2;
            if (name_len > name_leftlen)
            {
                SSL_DEBUG("name_len %d error,name_leftlen:%d !", name_len, name_leftlen);
                return -1;
            }
            
            *servername_len = name_len;
            memcpy(server_name, p_namebuf, name_len);

            find_server_name = 1;
        }        

        p_sslbuf += ext_len;
        left_len -= ext_len;
        if (find_server_name)
            break;
    }

    if (find_server_name)
    {
        return 0;
    }

    return -1;
}


