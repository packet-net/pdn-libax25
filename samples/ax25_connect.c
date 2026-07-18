// SPDX-License-Identifier: 0BSD
//
// ax25_connect - minimal connected-mode AX.25 client.
//
// Opens a reliable, acknowledged AX.25 *session* (SOCK_SEQPACKET, like TCP) to a
// remote station, sends one line typed on stdin, prints whatever comes back, and
// hangs up. This is the "call a station" client - a BBS login, keyboard chat,
// file/mail transfer: anything where you want a real, ordered connection.
//
// It uses ONLY the standard AF_AX25 socket API - there is nothing pdn-specific
// here. Run it under the pdn LD_PRELOAD shim (libax25_interpose.so) and the same
// unmodified binary talks to a pdn node instead of the (removed) Linux kernel
// AX.25 stack. See samples/README.md for the exact invocation.
//
//   cc -O2 -o ax25_connect ax25_connect.c

#include <netax25/ax25.h>   // ax25_address, struct sockaddr_ax25 (no -lax25 link)
#include <sys/socket.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Fill an ax25_address with the kernel's shifted-ASCII encoding of "CALL-SSID".
// (libax25's ax25_aton() normally does this; inlined so we link no library.)
static void encode_call(ax25_address *a, const char *s)
{
    int i = 0, ssid = 0;
    const char *dash = strchr(s, '-');
    for (; i < 6 && s[i] && s[i] != '-'; i++)
        a->ax25_call[i] = toupper((unsigned char)s[i]) << 1;
    for (; i < 6; i++)
        a->ax25_call[i] = ' ' << 1;          // pad the callsign to 6 chars
    if (dash)
        ssid = atoi(dash + 1);
    a->ax25_call[6] = (ssid & 0x0F) << 1;    // SSID lives in bits 1..4
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s REMOTECALL [MYCALL]\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_AX25, SOCK_SEQPACKET, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // Optionally bind our own callsign as the source of the connection.
    if (argc >= 3) {
        struct sockaddr_ax25 me = { .sax25_family = AF_AX25 };
        encode_call(&me.sax25_call, argv[2]);
        if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) {
            perror("bind"); return 1;
        }
    }

    // Connect to the remote station. This blocks through the AX.25 SABM/UA
    // handshake and returns 0 only once the link is really up.
    struct sockaddr_ax25 peer = { .sax25_family = AF_AX25 };
    encode_call(&peer.sax25_call, argv[1]);
    if (connect(fd, (struct sockaddr *)&peer, sizeof peer) < 0) {
        perror("connect"); return 1;
    }
    fprintf(stderr, "connected to %s\n", argv[1]);

    // Send one line typed on stdin...
    char line[512];
    if (fgets(line, sizeof line, stdin))
        if (write(fd, line, strlen(line)) < 0) { perror("write"); return 1; }

    // ...then print whatever the station sends back until it closes the link.
    // (A real terminal would select() over stdin + the socket to go both ways.)
    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0)
        fwrite(buf, 1, (size_t)n, stdout);

    close(fd);
    return 0;
}
