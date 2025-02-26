# コンパイル対象の実行ファイル名
NAME = ft_ping

# コンパイラとフラグ設定
CC = gcc
CFLAGS = -Wall -Wextra -Werror

# ソースファイルとオブジェクトファイル
SRC = ft_ping.c util/print_help.c
OBJ = $(SRC:.c=.o)

# デフォルトルール：すべてのファイルをコンパイルして実行ファイルを生成
all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# オブジェクトファイルの削除
clean:
	rm -f $(OBJ)

# 実行ファイルとオブジェクトファイルの削除
fclean: clean
	rm -f $(NAME)

# 再コンパイル
re: fclean all

.PHONY: all clean fclean re
