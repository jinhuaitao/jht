#!/bin/bash

set -e # 一旦发生错误，立即退出脚本

# 检测系统类型
if [ -f /etc/alpine-release ]; then
    echo "检测到 Alpine 系统"
    apk update
    apk add curl socat wget sudo nano
elif [ -f /etc/debian_version ]; then
    echo "检测到 Debian 系统"
    apt update && apt install -y curl socat wget sudo nano
else
    echo "无法检测到支持的系统类型，脚本仅支持 Alpine 和 Debian 系统。"
    exit 1
fi

# 下载远程脚本并检测
curl -sL https://gitlab.com/jinhuaitao66/jht/-/raw/main/jht.sh -o ~/jht.sh
if [ $? -ne 0 ]; then
    echo "下载 jht.sh 失败，请检查网络连接。"
    exit 1
fi

chmod +x ~/jht.sh
~/jht.sh
