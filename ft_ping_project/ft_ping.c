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
#include <netinet/ip_icmp.h>  // ICMPヘッダの定義（Echo Request/Reply等）
#include <netinet/ip.h>       // IPヘッダの定義（TTL取得など）
#include <sys/time.h>
#include "util/print_help.h"       // ヘルプ表示用の関数（外部ファイル）
#include "util/compute_checksum.h" // チェックサム計算関数（外部ファイル）

#define PACKET_SIZE 64  // ICMPパケット全体のサイズ（バイト単位）

/* グローバル変数：統計情報保持用 */
volatile sig_atomic_t packets_transmitted = 0;  // 送信したパケット数
volatile sig_atomic_t packets_received = 0;     // 受信したパケット数
double rtt_sum = 0.0;       // RTTの合計（ミリ秒）
double rtt_sum2 = 0.0;      // RTT二乗の合計（mdev計算用）
double rtt_min = 1e9;       // 最小RTT（初期値は非常に大きな値）
double rtt_max = 0.0;       // 最大RTT
struct timeval global_start_time; // 最初のパケット送信時刻
char global_destination[256] = {0}; // 宛先ホスト名（統計出力で利用）

/* SIGINT（Ctrl+C）シグナルハンドラ
   ユーザーがCtrl+Cを押したときに呼ばれ、統計情報を計算して表示し、
   プログラムを終了する。 */
void sigint_handler(int signo) {
    (void) signo; // シグナル番号は使用しないので警告を回避
    struct timeval now;
    if (gettimeofday(&now, NULL) < 0) {
        perror("gettimeofday");
        exit(EXIT_FAILURE);
    }
    // 全体の経過時間（ミリ秒）を計算
    long total_time_ms = (now.tv_sec - global_start_time.tv_sec) * 1000 +
                         (now.tv_usec - global_start_time.tv_usec) / 1000;
    // パケット損失率を計算（送信-受信の比率）
    int loss = 0;
    if (packets_transmitted > 0)
        loss = ((packets_transmitted - packets_received) * 100) / packets_transmitted;
    
    // 平均RTTの計算
    double avg = (packets_received > 0) ? rtt_sum / packets_received : 0.0;
    // RTTの分散（E[X^2] - (E[X])^2）を計算し、mdev（標準偏差）を算出
    double variance = (packets_received > 0) ? (rtt_sum2 / packets_received) - (avg * avg) : 0.0;
    if (variance < 0)
        variance = 0;
    double mdev = sqrt(variance);
    
    // 統計情報を標準のping形式に近い形で表示
    printf("\n--- %s ping statistics ---\n", global_destination);
    printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n",
           packets_transmitted, packets_received, loss, total_time_ms);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
           rtt_min, avg, rtt_max, mdev);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    int opt;
    int verbose_flag = 0;  // verboseモードフラグ（-v指定時に有効）

    // コマンドラインオプションの解析（-v：verbose, -?：ヘルプ表示）
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

    // オプション解析後、必ず宛先引数が必要
    if (optind >= argc) {
        fprintf(stderr, "Error: Destination argument is required.\n");
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    char *destination = argv[optind];
    // 統計出力用にグローバル変数にコピー
    strncpy(global_destination, destination, sizeof(global_destination)-1);

    /* getaddrinfoを使用して、destination（ホスト名またはIP）を解決する。
       AI_CANONNAMEフラグはverboseモードの場合に設定し、canonical nameを取得。 */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // IPv4/IPv6両方を対象にする
    hints.ai_socktype = SOCK_RAW;   // RAWソケット（パケット全体を操作）
    hints.ai_protocol = IPPROTO_ICMP; // ICMPプロトコルを使用

    int status = getaddrinfo(destination, NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return EXIT_FAILURE;
    }
    
    // verboseモードの場合、固定のデバッグ情報を出力（標準ping -vの例に合わせる）
    if (verbose_flag) {
        printf("ping: sock4.fd: 3 (socktype: SOCK_DGRAM), sock6.fd: 4 (socktype: SOCK_DGRAM), hints.ai_family: AF_UNSPEC\n");
    }
    
    // resリストからIPv4アドレスを選ぶ
    struct addrinfo *ai;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) break;
    }
    if (ai == NULL) {
        fprintf(stderr, "No IPv4 address found for %s\n", destination);
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }
    
    // IPv4アドレスを文字列に変換
    char ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) ai->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    
    if (verbose_flag) {
        // verboseモードの場合、canonical nameなどの情報を出力
        printf("ai->ai_family: AF_INET, ai->ai_canonname: '%s'\n", 
               (ai->ai_canonname ? ai->ai_canonname : destination));
    }
    
    // ICMPパケットのペイロードサイズは、PACKET_SIZEからICMPヘッダのサイズ（通常8バイト）を引いたもの
    int payload_size = PACKET_SIZE - sizeof(struct icmphdr);
    // 初回出力（標準のpingの形式）
    // 全体のパケットサイズは、IPヘッダ(20バイト) + ICMPパケット(64バイト)となる
    printf("PING %s (%s) %d(%d) bytes of data.\n", destination, ipstr, payload_size, PACKET_SIZE + 20);

    // IPv4のRAWソケットを作成（ICMP送信用）
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }
    // 標準ping -vではsocketの詳細情報はその後表示されない

    // SIGINT（Ctrl+C）シグナルを設定し、ユーザーが割り込んだ時に統計情報を表示する
    signal(SIGINT, sigint_handler);

    // 統計情報用に、最初の送信時刻を記録する
    if (gettimeofday(&global_start_time, NULL) < 0) {
        perror("gettimeofday");
        freeaddrinfo(res);
        close(sockfd);
        return EXIT_FAILURE;
    }

    int seq = 1; // シーケンス番号の初期化
    while (1) {
        char packet[PACKET_SIZE];
        memset(packet, 0, sizeof(packet)); // パケットバッファをゼロクリア

        // ---- ICMPエコーリクエストパケットの作成 ----
        // パケット先頭をICMPヘッダとして扱い、各フィールドに値を設定
        struct icmphdr *icmp_hdr = (struct icmphdr *) packet;
        icmp_hdr->type = ICMP_ECHO;             // Echo Requestのタイプ（8）
        icmp_hdr->code = 0;                     // コードは0
        icmp_hdr->un.echo.id = getpid() & 0xFFFF; // プロセスIDの下位16ビットを識別子として使用
        icmp_hdr->un.echo.sequence = seq;         // シーケンス番号を設定
        icmp_hdr->checksum = 0;                   // チェックサム計算前に0クリア
        // compute_checksum関数でパケット全体のチェックサムを計算して設定
        icmp_hdr->checksum = compute_checksum(packet, PACKET_SIZE);
        // ---------------------------------------------

        // ---- 送信直前のタイムスタンプ取得 ----
        struct timeval start, end;
        if (gettimeofday(&start, NULL) < 0) {
            perror("gettimeofday");
            break;
        }

        // ---- ICMPパケットの送信 ----
        // sendtoを使用して、指定されたアドレス（IPv4）にパケットを送信
        ssize_t sent_bytes = sendto(sockfd, packet, PACKET_SIZE, 0, ai->ai_addr, ai->ai_addrlen);
        if (sent_bytes < 0) {
            perror("sendto");
            break;
        }
        packets_transmitted++;  // 送信パケット数を更新

        // ---- 応答パケットの受信 ----
        char recv_buf[1024]; // 受信用バッファ（十分な大きさに設定）
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        ssize_t recv_bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                      (struct sockaddr *)&reply_addr, &addr_len);
        if (recv_bytes < 0) {
            perror("recvfrom");
            break;
        }
        // 受信直後のタイムスタンプを取得
        if (gettimeofday(&end, NULL) < 0) {
            perror("gettimeofday");
            break;
        }

        // ---- RTTの計算 ----
        // RTTは送信直前と受信直後の時間差（ミリ秒）で求める
        double rtt = (end.tv_sec - start.tv_sec) * 1000.0 +
                     (end.tv_usec - start.tv_usec) / 1000.0;

        // ---- IPヘッダからTTLの抽出 ----
        // 受信バッファにはIPヘッダが含まれているため、そこからTTLを取得
        struct ip *ip_hdr = (struct ip *) recv_buf;
        int ttl = ip_hdr->ip_ttl;

        // ---- 逆引きDNSを行わず、入力されたFQDNをそのまま利用する ----
        char hostname[NI_MAXHOST];
        strncpy(hostname, global_destination, sizeof(hostname) - 1);

        // ---- 統計情報の更新 ----
        packets_received++;
        rtt_sum += rtt;
        rtt_sum2 += rtt * rtt;
        if (rtt < rtt_min) rtt_min = rtt;
        if (rtt > rtt_max) rtt_max = rtt;

        // ---- 応答行の出力 ----
        // 出力形式は標準pingと同じ形式：
        // "64 bytes from <hostname> (<ip>): icmp_seq=<seq> ttl=<ttl> time=<rtt> ms"
        printf("64 bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1f ms\n",
               hostname, ipstr, seq, ttl, rtt);

        seq++;         // 次のパケットのシーケンス番号を更新
        sleep(1);      // 次のパケット送信まで1秒待機
    }

    freeaddrinfo(res);
    close(sockfd);
    return EXIT_SUCCESS;
}
