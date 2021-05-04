//20210503 https://github.com/dexgeh/http_parser/blob/master/http_parser.h
//by shawn
#ifndef http_parser_guard
#define http_parser_guard 1

#define HTTP_REQUEST 1
#define HTTP_RESPONSE 2

struct http_header {
    char *name, *value;
};

struct http_message {
    char type;

    char *method, *url;
    char *protocol;
    char *status, *line;

    #define HTTP_HEADER_MAX 16
    struct http_header headers[HTTP_HEADER_MAX];

    char *body;

    char connection_close;
    char connection_keepalive;
    char gzip_supported;
};

int http_parser(char *, struct http_message *, int);

#endif

