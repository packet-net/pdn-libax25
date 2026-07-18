// SPDX-License-Identifier: 0BSD
//
// ax25_answer - minimal connected-mode AX.25 LISTENER (an ax25d in miniature).
//
// Binds a callsign, listens for inbound AX.25 sessions (SOCK_SEQPACKET), and for
// each caller prints who called, sends a greeting, then echoes back every line
// the caller types until they disconnect. The connected-mode counterpart to
// ax25_ui_monitor.
//
// Standard AF_AX25 socket API only; run it under the pdn LD_PRELOAD shim to
// answer connections via a pdn node. See samples/README.md.
//
//   cc -O2 -o ax25_answer ax25_answer.c

#include <netax25/ax25.h>   // ax25_address, sockaddr_ax25, full_sockaddr_ax25
#include <sys/socket.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// "CALL-SSID" -> shifted-ASCII ax25_address (see ax25_connect.c for why inline).
static void encode_call(ax25_address *a, const char *s)
{
    int i = 0, ssid = 0;
    const char *dash = strchr(s, '-');
    for (; i < 6 && s[i] && s[i] != '-'; i++)
        a->ax25_call[i] = toupper((unsigned char)s[i]) << 1;
    for (; i < 6; i++)
        a->ax25_call[i] = ' ' << 1;
    if (dash)
        ssid = atoi(dash + 1);
    a->ax25_call[6] = (ssid & 0x0F) << 1;
}

// shifted-ASCII ax25_address -> "CALL-SSID".
static void decode_call(char *out, const ax25_address *a)
{
    int n = 0;
    for (int i = 0; i < 6; i++) {
        char c = (a->ax25_call[i] >> 1) & 0x7F;
        if (c != ' ')
            out[n++] = c;
    }
    int ssid = (a->ax25_call[6] >> 1) & 0x0F;
    if (ssid)
        n += sprintf(out + n, "-%d", ssid);
    out[n] = '\0';
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s MYCALL\n", argv[0]); return 2; }

    int fd = socket(AF_AX25, SOCK_SEQPACKET, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_ax25 me = { .sax25_family = AF_AX25 };
    encode_call(&me.sax25_call, argv[1]);
    if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) { perror("bind"); return 1; }
    if (listen(fd, 1) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "listening as %s\n", argv[1]);

    for (;;) {
        // Wait for the next caller. accept() returns a fresh fd for that session
        // and fills `peer` with the caller's callsign.
        struct full_sockaddr_ax25 peer;
        socklen_t plen = sizeof peer;
        int conn = accept(fd, (struct sockaddr *)&peer, &plen);
        if (conn < 0) { perror("accept"); break; }

        char who[16];
        decode_call(who, &peer.fsa_ax25.sax25_call);
        fprintf(stderr, "connect from %s\n", who);

        dprintf(conn, "Hello %s - you are connected. Type a line; I echo it.\n", who);

        // Echo each received line straight back until the caller disconnects.
        char buf[512];
        ssize_t n;
        while ((n = read(conn, buf, sizeof buf)) > 0)
            if (write(conn, buf, (size_t)n) < 0)
                break;

        close(conn);
        fprintf(stderr, "%s disconnected\n", who);
    }

    close(fd);
    return 0;
}
