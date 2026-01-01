/*
 * Copyright (c) 2025 Jebbari Marouane
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>      
#include <arpa/inet.h>    

#include "../inc/cypher_err.h"
#include "../inc/cypher_prot.h"


void cy_pad_add(CY_BUFF *buff)
{
    buff->head.cy_pad_flag = 1;
    buff->head.cy_pad_len = CY_AES_PAD_SIZE - buff->head.cy_len % CY_AES_PAD_SIZE;
    size_t newlen = buff->head.cy_len + buff->head.cy_pad_len;
    buff->buffer = realloc(buff->buffer, newlen);
    memset(buff->buffer + buff->head.cy_len, (int)buff->head.cy_pad_len, buff->head.cy_pad_len);
    buff->head.cy_len = newlen;
}

void cy_pad_rmv(CY_BUFF *buff)
{
    buff->head.cy_len = buff->head.cy_len - buff->head.cy_pad_len;
    buff->head.cy_pad_flag = 0;
    buff->head.cy_pad_len = 0;
}

void cy_header_exp(const CY_BUFF buff, uint8_t *out)
{
    uint64_t len = (uint64_t)buff.head.cy_len;

    /* 0..7: length big-endian */
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)((len >> (56 - 8*i)) & 0xFF);

    out[8]  = buff.head.cy_enc_flag;  out[9]  = buff.head.cy_enc_type;
    out[10] = buff.head.cy_key_flag;  out[11] = buff.head.cy_key_type;
    out[12] = buff.head.cy_hash_flag; out[13] = buff.head.cy_hash_type;
    out[14] = buff.head.cy_pad_flag;  out[15] = buff.head.cy_pad_len;
}

void cy_header_imp(const uint8_t *in, CY_BUFF *b)
{
    uint64_t len = 0;

    for (int i = 0; i < 8; i++) len = (len << 8) | (uint64_t)in[i];

    b->head.cy_len = (size_t)len;

    b->head.cy_enc_flag  = in[8];  b->head.cy_enc_type  = in[9];
    b->head.cy_key_flag  = in[10]; b->head.cy_key_type  = in[11];
    b->head.cy_hash_flag = in[12]; b->head.cy_hash_type = in[13];
    b->head.cy_pad_flag  = in[14]; b->head.cy_pad_len   = in[15];
}

void cy_inet_server(const char *port, int *clsd)
{
    int status, sd;
    struct addrinfo hints, *servinfo;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_flags    = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(NULL, port, &hints, &servinfo);
    if (status != 0) {
        fprintf(stderr, "gai error: %s\n", gai_strerror(status));
        exit(1);
    }

    sd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (sd == -1) cy_state("socket", -1);

    int opt = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) cy_state("setsockopt(SO_REUSEADDR)", -1);

    if (bind(sd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) cy_state("bind", -1);

    freeaddrinfo(servinfo);

    printf("Listening on port %s...\n", port);
    fflush(stdout);

    if (listen(sd, 1) == -1) cy_state("listen", -1);

    struct sockaddr_in clinfo;
    socklen_t addr_size = sizeof(clinfo);

    *clsd = accept(sd, (struct sockaddr *)&clinfo, &addr_size);
    if (*clsd == -1) cy_state("accept", -1);

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clinfo.sin_addr, ipstr, sizeof(ipstr));
    printf("Client connected from %s:%u\n", ipstr, (unsigned)ntohs(clinfo.sin_port));
    fflush(stdout);

    close(sd);
}

void cy_inet_client(const char *ipv4, const char *port, int *servsd)
{
    int status;
    struct addrinfo hints, *clinfo;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(ipv4, port, &hints, &clinfo);
    if (status != 0) {
        fprintf(stderr, "gai error: %s\n", gai_strerror(status));
        exit(1);
    }

    *servsd = socket(clinfo->ai_family, clinfo->ai_socktype, clinfo->ai_protocol);
    if (*servsd == -1) cy_state("socket", -1);

    if (connect(*servsd, clinfo->ai_addr, clinfo->ai_addrlen) == -1) cy_state("connect", -1);

    freeaddrinfo(clinfo);

    printf("Successfully connected to %s:%s\n", ipv4, port);
    fflush(stdout);
}