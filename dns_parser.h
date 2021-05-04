#ifndef __DNS_PARSER_H__
#define __DNS_PARSER_H__

#define DNS_QUERIES 12
#define DNS_DATA_OFFSET  12
#define DNS_TYPE_A_DATA_LENGTH  16
#define DNS_DATA_LENGTH  64 
#define DNS_MAX_NAME_LEN 253
#define DNS_DOT '.' //'.'的ASCII码


typedef enum {
    DNS_UDP = 0,
    DNS_TCP,
}DNS_TRANS_TYPE;

typedef struct {
    DNS_TRANS_TYPE trans_type;
    int requestID;//请求标识
	int requestFlag;//请求标志
	char*  dns_queries_data;
    unsigned short dns_queries_len;
	char  DNSname[DNS_DATA_LENGTH+1];//DNS名称
	unsigned short requestType;//查询类型	
	unsigned short  requestClass;//查询类
}DNS_REQUEST_INFO;    

int dns_parse(char* dns_pkt, unsigned short dns_pkt_len, DNS_REQUEST_INFO* dns_req);

#endif

