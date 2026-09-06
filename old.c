#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Cross-platform network headers
#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

// Initialize network library (Windows only)
int init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#endif
    return 1;
}

// Clean up network library (Windows only)
void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Parse MAC address string (supports aa:bb:cc... or aa-bb-cc... formats)
int parse_mac(const char *mac_str, unsigned char *mac_out) {
    unsigned int bytes[6];
    int filled = sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]);
    if (filled != 6) {
        filled = sscanf(mac_str, "%x-%x-%x-%x-%x-%x", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]);
    }

    if (filled != 6) return 0;

    for (int i = 0; i < 6; ++i) {
        mac_out[i] = (unsigned char) bytes[i];
    }
    return 1;
}

// Construct Magic Packet
void create_magic_packet(const unsigned char *mac, unsigned char *packet_out) {
    // First 6 bytes are 0xFF
    memset(packet_out, 0xFF, 6);
    // Repeat MAC address 16 times
    for (int i = 0; i < 16; ++i) {
        memcpy(packet_out + 6 + (i * 6), mac, 6);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        printf("Usage:\n");
        printf("  Local broadcast:     %s <MAC>\n", argv[0]);
        printf("  Target IP & Domain:  %s <MAC> <IP>\n", argv[0]);
        printf("Examples:\n");
        printf("  %s 11:22:33:44:55:66\n", argv[0]);
        printf("  %s 11:22:33:44:55:66 192.168.1.100\n", argv[0]);
        return 1;
    }

    const char *mac_arg = argv[1];
    const char *ip_arg = (argc == 3) ? argv[2] : "255.255.255.255";

    unsigned char mac[6];
    if (!parse_mac(mac_arg, mac)) {
        fprintf(stderr, "Error: Invalid MAC address format.\n");
        return 1;
    }

    if (!init_network()) {
        fprintf(stderr, "Error: Network initialization failed.\n");
        return 1;
    }

    // Create UDP Socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: Failed to create socket.\n");
        cleanup_network();
        return 1;
    }

    // Enable Broadcast Option
    int broadcast_enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *) &broadcast_enable, sizeof(broadcast_enable)) == SOCKET_ERROR) {
        fprintf(stderr, "Warning: Failed to set socket broadcast option.\n");
    }

    // Build the Magic Packet
    unsigned char packet[102];
    create_magic_packet(mac, packet);

    // Setup Target Address (Port 9 is the standard WOL port)
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(9);
    target_addr.sin_addr.s_addr = inet_addr(ip_arg);

    if (target_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Error: Invalid IP address.\n");
        closesocket(sock);
        cleanup_network();
        return 1;
    }

    // Send Magic Packet to target IP
    int bytes_sent = sendto(sock, (const char *) packet, sizeof(packet), 0, (struct sockaddr *) &target_addr, sizeof(target_addr));
    if (bytes_sent == SOCKET_ERROR) {
        fprintf(stderr, "Error: Failed to send magic packet.\n");
    } else {
        printf("Success: Sent magic packet to %s (%d bytes).\n", ip_arg, bytes_sent);
    }

    // If target IP is provided, also send to the local broadcast domain
    if (argc == 3 && strcmp(ip_arg, "255.255.255.255") != 0) {
        target_addr.sin_addr.s_addr = INADDR_BROADCAST; // 255.255.255.255
        sendto(sock, (const char *) packet, sizeof(packet), 0, (struct sockaddr *) &target_addr, sizeof(target_addr));
        printf("Success: Synchronously sent magic packet to local broadcast domain (255.255.255.255).\n");
    }

    // Resource Cleanup
    closesocket(sock);
    cleanup_network();
    return 0;
}
