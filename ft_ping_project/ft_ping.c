#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
    printf("  -e <identifier>    define identifier for ping session, default is random for\n");
    printf("                     SOCK_RAW and kernel defined for SOCK_DGRAM\n");
    printf("                     Imply using SOCK_RAW (for IPv4 only for identifier 0)\n");
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

    // 解析結果の表示（ここから実際の処理を実装）
    printf("Destination: %s\n", destination);
    if (verbose_flag) {
        printf("Verbose mode enabled.\n");
    }

    return EXIT_SUCCESS;
}
