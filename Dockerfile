# Debian最新（または指定バージョン例: debian:10）イメージを利用
FROM debian:latest

# 必要なパッケージのインストール
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    iputils-ping \
    net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 作業ディレクトリの設定
WORKDIR /usr/src/app

# ソースコードをコンテナ内にコピー（ホスト側のカレントディレクトリを想定）
COPY . .

# コンテナ起動時にbashを起動
CMD ["bash"]
