#include <stdio.h>
#include <stdlib.h>

/*
 * ft_ping - 独自の ping コマンド実装
 *
 * TODO:
 *   - コマンドライン引数の解析
 *   - ICMPエコーリクエストの作成・送信
 *   - ICMPエコーリプライの受信とRTTの計測
 *   - 必須オプション（例: -v, -?）の処理
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname/IP>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("ft_ping: %s に対して ping を実行します。\n", argv[1]);
    // ここに実装を追加していく

    return EXIT_SUCCESS;
}
