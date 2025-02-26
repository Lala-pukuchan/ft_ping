#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>  // ICMPヘッダ用
#include <sys/time.h>
#include "util/print_help.h"       // ヘルプ表示用の関数が定義されたヘッダ
#include "util/compute_checksum.h" // compute_checksum関数が定義されたヘッダ

#define PACKET_SIZE 64

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

    // オプション解析後、非オプション引数は optind 以降に残る
    if (optind >= argc) {
        fprintf(stderr, "Error: Destination argument is required.\n");
        print_help(argv[0]);
        return EXIT_FAILURE;
    }

    char *destination = argv[optind];
    printf("Destination: %s\n", destination);
    if (verbose_flag) {
        printf("Verbose mode enabled.\n");
    }

    /* 
     * destination は、IPアドレスまたはFQDNとして設定可能です。
     * getaddrinfo を用いて名前解決を行い、IPv4アドレスを取得します。
     */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4に限定
    hints.ai_socktype = SOCK_RAW;    // RAWソケット
    hints.ai_protocol = IPPROTO_ICMP; // ICMPプロトコル

    int status = getaddrinfo(destination, NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return EXIT_FAILURE;
    }
    
    // 解決されたIPv4アドレスの表示
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    printf("Resolved IP address: %s\n", ipstr);

    // RAWソケット（ICMP用）の作成
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }
    printf("Raw socket created successfully.\n");

    // ---- ICMPエコーリクエストパケットの作成 ----
    char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));

    // ICMPヘッダを構築
    struct icmphdr *icmp_hdr = (struct icmphdr *) packet;
    icmp_hdr->type = ICMP_ECHO;             // エコーリクエスト（タイプ8）
    icmp_hdr->code = 0;                     // コードは0
    icmp_hdr->un.echo.id = getpid() & 0xFFFF;  // 識別子（プロセスIDの下位16ビット）
    icmp_hdr->un.echo.sequence = 1;         // シーケンス番号（初回なので1）

    // チェックサム計算前は0に設定
    icmp_hdr->checksum = 0;
    // パケット全体のチェックサムを計算し、設定する
    icmp_hdr->checksum = compute_checksum(packet, PACKET_SIZE);

    printf("ICMP Packet created:\n");
    printf("  Type: %d\n", icmp_hdr->type);
    printf("  Code: %d\n", icmp_hdr->code);
    printf("  Identifier: %d\n", icmp_hdr->un.echo.id);
    printf("  Sequence: %d\n", icmp_hdr->un.echo.sequence);
    printf("  Checksum: 0x%x\n", icmp_hdr->checksum);
    // ----------------------------------------------

    // ---- RTT計測用のタイムスタンプ取得（送信直前） ----
    struct timeval start, end;
    if (gettimeofday(&start, NULL) < 0) {
        perror("gettimeofday");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }

    // ---- パケットの送信 ----
    ssize_t sent_bytes = sendto(sockfd, packet, PACKET_SIZE, 0, res->ai_addr, res->ai_addrlen);
    if (sent_bytes < 0) {
        perror("sendto");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }
    printf("Sent %zd bytes to %s\n", sent_bytes, ipstr);

    // ---- 応答パケットの受信 ----
    char recv_buf[1024];
    struct sockaddr_in reply_addr;
    socklen_t addr_len = sizeof(reply_addr);
    ssize_t recv_bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                  (struct sockaddr *)&reply_addr, &addr_len);
    if (recv_bytes < 0) {
        perror("recvfrom");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    // ---- RTT計測用のタイムスタンプ取得（受信直後） ----
    if (gettimeofday(&end, NULL) < 0) {
        perror("gettimeofday");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }

    // RTT（ラウンドトリップタイム）の計算（ミリ秒単位）
    double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                 (end.tv_usec - start.tv_usec) / 1000.0;
    
    // 受信したパケットの送信元IPアドレスの表示
    char reply_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &reply_addr.sin_addr, reply_ip, sizeof(reply_ip));
    printf("Received %zd bytes from %s\n", recv_bytes, reply_ip);
    printf("RTT: %.2f ms\n", rtt);

    // 後続の処理（パケット解析等）はここに追加可能

    freeaddrinfo(res);
    close(sockfd);
    return EXIT_SUCCESS;
}
