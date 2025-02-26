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

#define PACKET_SIZE 64

void print_help(const char *progname) {
    printf("Usage\n");
    printf("  %s [options] <destination>\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  <destination>      dns name or ip address\n");
    printf("  -a                 use audible ping\n");
    printf("  -A                 use adaptive ping\n");
    printf("  -B                 sticky source address\n");
    printf("  -c <count>         stop after <count> replies\n");
    printf("  -C                 call connect() syscall on socket creation\n");
    printf("  -D                 print timestamps\n");
    printf("  -d                 use SO_DEBUG socket option\n");
    printf("  -e <identifier>    define identifier for ping session\n");
    printf("  -f                 flood ping\n");
    printf("  -h                 print help and exit\n");
    printf("  -I <interface>     either interface name or address\n");
    printf("  -i <interval>      seconds between sending each packet\n");
    printf("  -L                 suppress loopback of multicast packets\n");
    printf("  -l <preload>       send <preload> number of packages while waiting replies\n");
    printf("  -m <mark>          tag the packets going out\n");
    printf("  -M <pmtud opt>     define mtu discovery, can be one of <do|dont|want>\n");
    printf("  -n                 no dns name resolution\n");
    printf("  -O                 report outstanding replies\n");
    printf("  -p <pattern>       contents of padding byte\n");
    printf("  -q                 quiet output\n");
    printf("  -Q <tclass>        use quality of service <tclass> bits\n");
    printf("  -s <size>          use <size> as number of data bytes to be sent\n");
    printf("  -S <size>          use <size> as SO_SNDBUF socket option value\n");
    printf("  -t <ttl>           define time to live\n");
    printf("  -U                 print user-to-user latency\n");
    printf("  -v                 verbose output\n");
    printf("  -V                 print version and exit\n");
    printf("  -w <deadline>      reply wait <deadline> in seconds\n");
    printf("  -W <timeout>       time to wait for response\n");
    printf("\n");
    printf("IPv4 options:\n");
    printf("  -4                 use IPv4\n");
    printf("  -b                 allow pinging broadcast\n");
    printf("  -R                 record route\n");
    printf("  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>\n");
    printf("\n");
    printf("IPv6 options:\n");
    printf("  -6                 use IPv6\n");
    printf("  -F <flowlabel>     define flow label, default is random\n");
    printf("  -N <nodeinfo opt>  use icmp6 node info query, try <help> as argument\n");
    printf("\n");
    printf("For more details see ping(8).\n");
}

// チェックサム計算関数（ICMPパケット用）
unsigned short compute_checksum(void *buf, int len) {
    unsigned short *data = buf;
    unsigned int sum = 0;
    
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        unsigned short last_byte = 0;
        *((unsigned char *)&last_byte) = *(unsigned char *)data;
        sum += last_byte;
    }
    
    // 上位16ビットと下位16ビットを足す
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
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
