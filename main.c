#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

#include <winsock2.h>

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

int init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#endif
    return 1;
}

void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

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

void create_magic_packet(const unsigned char *mac, unsigned char *packet_out) {
    memset(packet_out, 0xFF, 6);
    for (int i = 0; i < 16; ++i) {
        memcpy(packet_out + 6 + (i * 6), mac, 6);
    }
}

int main(int argc, char *argv[]) {
    // 默认指向完整的 argv[0]
    const char *exe_name = argv[0];

    // 跨平台提取纯文件名 (去掉路径)
    const char *last_slash = strrchr(argv[0], '/');    // 适用于 Linux / macOS / MSYS
#ifdef _WIN32
    const char *last_backslash = strrchr(argv[0], '\\'); // 适用于 Windows 原生路径
    if (last_backslash > last_slash) {
        last_slash = last_backslash;
    }
#endif

    // 如果找到了任意斜杠, 指针向后移动一位即为纯文件名
    if (last_slash != NULL) {
        exe_name = last_slash + 1;
    }

    // 参数范围调整为 2 到 4 个
    if (argc < 2 || argc > 4) {
        printf("\nUsage:\n");
        printf("  Local broadcast (Port 9):   %s <MAC>\n", exe_name);
        printf("  Target IP Unicast (Port 9): %s <MAC> <IP>\n", exe_name);
        printf("  Target IP & Custom Port:    %s <MAC> <IP> <PORT>\n", exe_name);
        printf("\nExamples:\n");
        printf("  %s 11:22:33:44:55:66\n", exe_name);
        printf("  %s 11:22:33:44:55:66 192.168.1.20\n", exe_name);
        printf("  %s 11:22:33:44:55:66 203.0.113.50 9090\n", exe_name);

        return 1;
    }

    const char *mac_arg = argv[1];
    unsigned char mac[6];
    if (!parse_mac(mac_arg, mac)) {
        fprintf(stderr, "Error: Invalid MAC address format.\n");
        return 1;
    }

    // 默认参数设置
    char ip_clean[64] = "255.255.255.255";
    int target_port = 9;

    // 1. 如果输入了 IP 参数 (情况 2 和 情况 3)
    if (argc >= 3) {
        strncpy(ip_clean, argv[2], sizeof(ip_clean) - 1);
        ip_clean[sizeof(ip_clean) - 1] = '\0';
    }

    // 2. 如果输入了自定义端口 (情况 3)
    if (argc == 4) {
        target_port = atoi(argv[3]);
        if (target_port <= 0 || target_port > 65535) {
            fprintf(stderr, "Error: Invalid port number.\n");
            return 1;
        }
    }

    if (!init_network()) {
        fprintf(stderr, "Error: Network initialization failed.\n");
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Error: Failed to create socket.\n");
        cleanup_network();
        return 1;
    }

    // 仅在本地广播 (255.255.255.255) 时此选项必须开启, 单播时开启不影响使用
    int broadcast_enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *) &broadcast_enable, sizeof(broadcast_enable)) == SOCKET_ERROR) {
        fprintf(stderr, "Warning: Failed to set socket broadcast option.\n");
    }

    unsigned char packet[102];
    create_magic_packet(mac, packet);

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    target_addr.sin_addr.s_addr = inet_addr(ip_clean);

    if (target_addr.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Error: Invalid IP address.\n");
        closesocket(sock);
        cleanup_network();
        return 1;
    }

    // 统一发送逻辑: 无论广播还是单播, 均只发送一次
    int bytes_sent = sendto(sock, (const char *) packet, sizeof(packet), 0, (struct sockaddr *) &target_addr, sizeof(target_addr));
    if (bytes_sent == SOCKET_ERROR) {
        fprintf(stderr, "Error: Failed to send magic packet.\n");
    } else {
        if (argc == 2) {
            printf("Success: Sent magic packet to local broadcast %s:%d (%d bytes).\n", ip_clean, target_port, bytes_sent);
        } else {
            printf("Success: Sent unicast magic packet to %s:%d (%d bytes).\n", ip_clean, target_port, bytes_sent);
        }
    }

    closesocket(sock);
    cleanup_network();

    return 0;
}
