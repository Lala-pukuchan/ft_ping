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
#include <netinet/ip_icmp.h>
#include "util/print_help.h"  // ヘッダーファイルをインクルード

#define PACKET_SIZE 64


// ICMPパケット用のチェックサム計算関数
// 与えられたバッファ内のデータを16ビット単位で読み込み、
// 全体の1の補数チェックサムを計算して返す。
unsigned short compute_checksum(void *buf, int len) {
    // バッファを16ビット単位で扱うため、unsigned short 型のポインタにキャスト
    unsigned short *data = buf;
    // チェックサム計算用の変数（32ビットで保持し、オーバーフロー処理も含む）
    unsigned int sum = 0;
    
    // 2バイト（16ビット）ずつデータを読み込み、加算していくループ
    while (len > 1) {
        // 現在の16ビット値をsumに加算し、dataポインタを次に進める
        sum += *data++;
        // 2バイト分読み込んだので、残りの長さを2バイト分減らす
        len -= 2;
    }
    
    // データ長が奇数の場合、最後の1バイトが残るので、その1バイトを処理する
    if (len == 1) {
        // 残りの1バイト分のデータを格納するために、変数を0で初期化
        unsigned short last_byte = 0;
        // dataをunsigned char型にキャストして、最後の1バイトを取得し、
        // last_byteの下位バイトにセットする
        *((unsigned char *)&last_byte) = *(unsigned char *)data;
        // 取得した1バイト分をsumに加算する
        sum += last_byte;
    }
    
    // sumの上位16ビットと下位16ビットのキャリーを加算して調整する
    // まず、上位16ビットと下位16ビットを分けて加算する
    sum = (sum >> 16) + (sum & 0xFFFF);
    // もしさらにキャリーが生じた場合、そのキャリーを再度加算する
    sum += (sum >> 16);
    
    // 最後に、1の補数（全ビットの反転）を計算してチェックサムとして返す
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    int opt;
    int verbose_flag = 0;

    // オプション解析: -v は verbose、-? はヘルプ表示
    while ((opt = getopt(argc, argv, "v?")) != -1) {
        switch (opt) {
            case 'v':
                verbose_flag = 1;
                break;
            case '?':
                print_help(argv[0]);  // print_help関数の呼び出し
                return EXIT_SUCCESS;
            default:
                print_help(argv[0]);  // print_help関数の呼び出し
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
     * destination は、IPアドレスまたはFQDNとして設定できます。
     * 以下の処理では getaddrinfo を用いて名前解決を行い、IPv4アドレスを取得します。
     */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 に限定
    hints.ai_socktype = SOCK_RAW;    // RAW ソケット
    hints.ai_protocol = IPPROTO_ICMP; // ICMP プロトコル

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
    icmp_hdr->type = ICMP_ECHO;    // エコーリクエスト（8）
    icmp_hdr->code = 0;            // コードは0
    icmp_hdr->un.echo.id = getpid() & 0xFFFF;  // 識別子（プロセスIDを利用）
    icmp_hdr->un.echo.sequence = 1;            // シーケンス番号（最初のパケットなので1）

    // チェックサム計算前は0に設定
    icmp_hdr->checksum = 0;
    // パケット全体のチェックサムを計算して設定
    icmp_hdr->checksum = compute_checksum(packet, PACKET_SIZE);

    printf("ICMP Packet created:\n");
    printf("  Type: %d\n", icmp_hdr->type);
    printf("  Code: %d\n", icmp_hdr->code);
    printf("  Identifier: %d\n", icmp_hdr->un.echo.id);
    printf("  Sequence: %d\n", icmp_hdr->un.echo.sequence);
    printf("  Checksum: 0x%x\n", icmp_hdr->checksum);
    // ----------------------------------------------

    // 今後、ここから送信および受信の処理を実装していきます

    freeaddrinfo(res);
    close(sockfd);
    return EXIT_SUCCESS;
}
