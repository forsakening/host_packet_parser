#ifndef _SSL_PARSER_H_
#define _SSL_PARSER_H_

int ssl_clienthello_parser_servername(unsigned char* ssl_buf, 
                                      unsigned int ssl_len, 
                                      unsigned char* server_name, 
                                      unsigned int* servername_len);

#endif