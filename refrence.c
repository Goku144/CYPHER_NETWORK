#include <inttypes.h>
//         CY_BUFF buf;
//         cy_read_line(STDIN_FILENO, &buf.buffer, &buf.head.cy_len);
//         printf("old length: %zu\n", buf.head.cy_len);
//         cy_pad_add(&buf);

//         uint8_t *buffout = malloc(CY_HEADER_SIZE);
//         cy_header_exp(buf, buffout);
        
//         buffout = realloc(buffout, buf.head.cy_len + CY_HEADER_SIZE);
//         memcpy(buffout + CY_HEADER_SIZE, buf.buffer, buf.head.cy_len);

//         CY_BUFF buffin;
//         cy_header_imp(buffout, &buffin);
//         buffin.buffer = malloc(buffin.head.cy_len);
//         memcpy(buffin.buffer, buffout + CY_HEADER_SIZE, buf.head.cy_len);

    
//         for (size_t i = 0; i < buffin.head.cy_len; i++)
//         {
//             printf("%c", (char) buffin.buffer[i]);
//         }
        
//         cy_write(STDOUT_FILENO, buf.buffer, buf.head.cy_len);
//         printf("\n");
//         printf("new length: %zu\n", buf.head.cy_len);

typedef int size_t;

struct in_addr
{
    uint32_t s_addr
};

struct sockaddr // generic for sockaddr like ipv4 and ipv6
{
    unsigned short sa_family;
    char sa_data[14]; 
};

struct sockaddr_in
{
    short int sin_family;
    unsigned short int sin_port; // Port number
    struct in_addr sin_addr; // Internet address
    unsigned char sin_zero[8]; // Same size as struct sockaddr
};

struct addrinfo // the struct 
{
    int ai_flag; //
    int ai_family; // AI_INET
    int ai_socktype; // AI_STREAM
    int ai_protocol; // 0 is ANY 
    size_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *next;
};

// in the ntop we use the INET_ADDRSTRLEN
/*
    export information to sockaddr (sockaddr_in)
    inet_pton(AF_INET, "192.168.1.137", &(sa.sin_addr));
    import information from sockaddr (sockaddr_in)
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sa.sin_addr), buff, INET_ADDRSTRLEN)
*/