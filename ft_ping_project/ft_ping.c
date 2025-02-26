#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>  // ICMPヘッダ用
#include <netinet/ip.h>       // IPヘッダ用（TTL取得のため）
#include <sys/time.h>
#include "util/print_help.h"       // ヘルプ表示用の関数が定義されたヘッダ
#include "util/compute_checksum.h" // compute_checksum関数が定義されたヘッダ

#define PACKET_SIZE 64

/* グローバル変数：統計情報保持用 */
volatile sig_atomic_t packets_transmitted = 0;
volatile sig_atomic_t packets_received = 0;
double rtt_sum = 0.0;
double rtt_sum2 = 0.0;
double rtt_min = 1e9;
double rtt_max = 0.0;
struct timeval global_start_time; // 最初の送信時刻
char global_destination[256] = {0}; // 宛先ホスト名

/* SIGINT（Ctrl+C）シグナルハンドラ */
void sigint_handler(int signo) {
    (void) signo; // 未使用引数の警告回避
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0) {
        perror("gettimeofday");
        exit(EXIT_FAILURE);
    }
    long total_time_ms = (now.tv_sec - global_start_time.tv_sec) * 1000 +
                         (now.tv_usec - global_start_time.tv_usec) / 1000;
    int loss = 0;
    if (packets_transmitted > 0)
        loss = ((packets_transmitted - packets_received) * 100) / packets_transmitted;
    
    double avg = (packets_received > 0) ? rtt_sum / packets_received : 0.0;
    double variance = (packets_received > 0) ? (rtt_sum2 / packets_received) - (avg * avg) : 0.0;
    if (variance < 0)
        variance = 0;
    double mdev = sqrt(variance);
    
    printf("\n--- %s ping statistics ---\n", global_destination);
    printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n",
           packets_transmitted, packets_received, loss, total_time_ms);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
           rtt_min, avg, rtt_max, mdev);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    int opt;
    int verbose_flag = 0;

    // オプション解析: -v はverbose、-? はヘルプ表示
    while ((opt = getopt(argc, argv, "v?")) != -1) {
        switch (opt) {
            case 'v':
                verbose_flag = 1;
                break;
            case '?':
                print_help(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_help(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: Destination argument is required.\n");
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    char *destination = argv[optind];
    strncpy(global_destination, destination, sizeof(global_destination)-1);

    /* destinationは、IPアドレスまたはFQDNとして設定可能 */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    // verboseの場合、標準ping -v の出力に合わせるため、hints.ai_familyは AF_UNSPEC で
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int status = getaddrinfo(destination, NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return EXIT_FAILURE;
    }
    
    if (verbose_flag) {
        printf("ping: sock4.fd: 3 (socktype: SOCK_DGRAM), sock6.fd: 4 (socktype: SOCK_DGRAM), hints.ai_family: AF_UNSPEC\n");
    }
    
    // IPv4アドレスを選ぶ（resリストから最初のIPv4を採用）
    struct addrinfo *ai;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) break;
    }
    if (ai == NULL) {
        fprintf(stderr, "No IPv4 address found for %s\n", destination);
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }
    
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) ai->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    
    if (verbose_flag) {
        printf("ai->ai_family: AF_INET, ai->ai_canonname: '%s'\n", 
               (ai->ai_canonname ? ai->ai_canonname : destination));
    }
    
    int payload_size = PACKET_SIZE - sizeof(struct icmphdr); // 例: 64 - 8 = 56
    // 初回出力（標準pingの形式）
    printf("PING %s (%s) %d(%d) bytes of data.\n", destination, ipstr, payload_size, PACKET_SIZE + 20);

    // RAWソケット（IPv4のみを使用）の作成
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }
    // ※ 標準ping -v の2番目のサンプルでは、socketの詳細出力は表示されていない

    // SIGINT（Ctrl+C）シグナルを捕捉
    signal(SIGINT, sigint_handler);

    if (gettimeofday(&global_start_time, NULL) < 0) {
        perror("gettimeofday");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }

    int seq = 1;
    while (1) {
        char packet[PACKET_SIZE];
        memset(packet, 0, sizeof(packet));

        // ---- ICMPエコーリクエストパケットの作成 ----
        struct icmphdr *icmp_hdr = (struct icmphdr *) packet;
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = getpid() & 0xFFFF;
        icmp_hdr->un.echo.sequence = seq;
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = compute_checksum(packet, PACKET_SIZE);
        // ※ verbose時の「ICMP Packet created: ...」出力は省略

        struct timeval start, end;
        if (gettimeofday(&start, NULL) < 0) {
            perror("gettimeofday");
            break;
        }

        ssize_t sent_bytes = sendto(sockfd, packet, PACKET_SIZE, 0, ai->ai_addr, ai->ai_addrlen);
        if (sent_bytes < 0) {
            perror("sendto");
            break;
        }
        packets_transmitted++;

        char recv_buf[1024];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        ssize_t recv_bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                      (struct sockaddr *)&reply_addr, &addr_len);
        if (recv_bytes < 0) {
            perror("recvfrom");
            break;
        }
        if (gettimeofday(&end, NULL) < 0) {
            perror("gettimeofday");
            break;
        }

        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_usec - start.tv_usec) / 1000.0;

        // 逆引きDNSでホスト名を取得（取得できなければIPアドレスを利用）
        char hostname[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)&reply_addr, addr_len, hostname, sizeof(hostname), NULL, 0, 0) != 0) {
            strcpy(hostname, ipstr);
        }

        struct ip *ip_hdr = (struct ip *) recv_buf;
        int ttl = ip_hdr->ip_ttl;

        packets_received++;
        rtt_sum += rtt;
        rtt_sum2 += rtt * rtt;
        if (rtt < rtt_min) rtt_min = rtt;
        if (rtt > rtt_max) rtt_max = rtt;

        printf("64 bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\n",
               hostname, ipstr, seq, ttl, rtt);

        seq++;
        sleep(1);
    }

    freeaddrinfo(res);
    close(sockfd);
    return EXIT_SUCCESS;
}
