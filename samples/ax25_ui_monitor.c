// SPDX-License-Identifier: 0BSD
//
// ax25_ui_monitor - minimal UI/datagram receiver.
//
// Binds a callsign on a datagram (SOCK_DGRAM) socket and prints every inbound
// AX.25 UI frame heard on the port as:
//
//     SRC>DEST [PID] text
//
// The datagram counterpart to ax25_answer: no connection, just listen. pdn
// delivers all UI heard on the bound port (promiscuous), so this is a live
// monitor of beacons/APRS/announcements.
//
// Standard AF_AX25 socket API only; run it under the pdn LD_PRELOAD shim to hear
// UI via a pdn node. See samples/README.md.
//
//   cc -O2 -o ax25_ui_monitor ax25_ui_monitor.c

#include <netax25/ax25.h>   // ax25_address, sockaddr_ax25, SOL_AX25, AX25_PIDINCL
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

    int fd = socket(AF_AX25, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_ax25 me = { .sax25_family = AF_AX25 };
    encode_call(&me.sax25_call, argv[1]);
    if (bind(fd, (struct sockaddr *)&me, sizeof me) < 0) { perror("bind"); return 1; }

    // Ask for the AX.25 PID byte to be prepended to each datagram, so we can show
    // it. (This is the same AX25_PIDINCL convention used to send IP over AX.25.)
    int on = 1;
    setsockopt(fd, SOL_AX25, AX25_PIDINCL, &on, sizeof on);

    fprintf(stderr, "monitoring UI on %s ...\n", argv[1]);
    for (;;) {
        // recvfrom() returns one whole UI frame and fills `src` with the sender.
        struct sockaddr_ax25 src;
        socklen_t slen = sizeof src;
        unsigned char buf[512];
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0,
                             (struct sockaddr *)&src, &slen);
        if (n < 0) { perror("recvfrom"); break; }
        if (n < 1) continue;                 // need at least the PID byte

        char from[16];
        decode_call(from, &src.sax25_call);
        // With AX25_PIDINCL the first byte is the PID; the rest is the payload.
        // DEST is our bound port callsign (what we are listening on).
        printf("%s>%s [%02X] %.*s\n",
               from, argv[1], buf[0], (int)(n - 1), buf + 1);
        fflush(stdout);
    }

    close(fd);
    return 0;
}
