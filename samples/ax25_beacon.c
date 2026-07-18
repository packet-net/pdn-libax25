// SPDX-License-Identifier: 0BSD
//
// ax25_beacon - minimal UI/datagram sender.
//
// Sends ONE connectionless AX.25 UI frame (SOCK_DGRAM, like a UDP packet) from
// your callsign to a destination, then exits. Fire-and-forget: no connection, no
// acknowledgement, may reach everyone or no-one - a beacon, an announcement, an
// APRS position. It uses the default PID 0xF0 ("no Layer 3"), the beacon/APRS
// default.
//
// Standard AF_AX25 socket API only; run it under the pdn LD_PRELOAD shim to emit
// the UI frame via a pdn node. See samples/README.md.
//
//   cc -O2 -o ax25_beacon ax25_beacon.c

#include <netax25/ax25.h>   // ax25_address, struct sockaddr_ax25 (no -lax25 link)
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

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s MYCALL DEST [text...]\n", argv[0]);
        return 2;
    }
    const char *text = (argc >= 4) ? argv[3] : "beacon from pdn";

    // A datagram socket needs no connection - just open, bind, send.
    int fd = socket(AF_AX25, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    // Bind our callsign: it becomes the UI frame's source address.
    struct sockaddr_ax25 me = { .sax25_family = AF_AX25 };
    encode_call(&me.sax25_call, argv[1]);
    if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) { perror("bind"); return 1; }

    // Address one UI frame to the destination and send it. That is the whole job.
    struct sockaddr_ax25 dest = { .sax25_family = AF_AX25 };
    encode_call(&dest.sax25_call, argv[2]);
    ssize_t n = sendto(fd, text, strlen(text), 0,
                       (struct sockaddr *)&dest, sizeof dest);
    if (n < 0) { perror("sendto"); return 1; }

    fprintf(stderr, "sent %zd bytes: %s > %s\n", n, argv[1], argv[2]);
    close(fd);
    return 0;
}
