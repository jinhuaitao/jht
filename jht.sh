#!/bin/bash

# 函数：启用 BBR
enable_bbr() {
    echo "正在启用 BBR..."
    echo "net.core.default_qdisc = fq
    net.ipv4.tcp_congestion_control = bbr
    net.ipv4.tcp_rmem = 8192 262144 536870912
    net.ipv4.tcp_wmem = 4096 16384 536870912
    net.ipv4.tcp_adv_win_scale = -2
    net.ipv4.tcp_collapse_max_bytes = 6291456
    net.ipv4.tcp_notsent_lowat = 131072
    net.ipv4.ip_local_port_range = 1024 65535
    net.core.rmem_max = 536870912
    net.core.wmem_max = 536870912
    net.core.somaxconn = 32768
    net.core.netdev_max_backlog = 32768
    net.ipv4.tcp_max_tw_buckets = 65536
    net.ipv4.tcp_abort_on_overflow = 1
    net.ipv4.tcp_slow_start_after_idle = 0
    net.ipv4.tcp_timestamps = 1
    net.ipv4.tcp_syncookies = 0
    net.ipv4.tcp_syn_retries = 3
    net.ipv4.tcp_synack_retries = 3
    net.ipv4.tcp_max_syn_backlog = 32768
    net.ipv4.tcp_fin_timeout = 15
    net.ipv4.tcp_keepalive_intvl = 3
    net.ipv4.tcp_keepalive_probes = 5
    net.ipv4.tcp_keepalive_time = 600
    net.ipv4.tcp_retries1 = 3
    net.ipv4.tcp_retries2 = 5
    net.ipv4.tcp_no_metrics_save = 1
    net.ipv4.ip_forward = 1
    fs.file-max = 104857600
    fs.inotify.max_user_instances = 8192
    fs.nr_open = 1048576" >> /etc/sysctl.conf

    sysctl -p
    sysctl net.ipv4.tcp_available_congestion_control
    lsmod | grep bbr
    echo "BBR 启用成功。"
    return_to_script
}

# 函数：安装所需依赖
install_dependencies() {
    echo "正在安装所需依赖..."
    apt update -y
    apt install -y curl socat wget sudo nano iptables
    echo "依赖安装完成。"
    return_to_script
}

# 函数：安装 TuiC
install_tuic() {
    echo "开始安装 TuiC..."
    mkdir -p /opt/tuic && cd /opt/tuic || exit

    read -p "请选择架构：1. ARM  2. X86 :" architecture_choice

    case "$architecture_choice" in
        1)
            wget https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/ARM/tuic-server-1.0.0-aarch64-unknown-linux-gnu -O tuic-server
            ;;
        2)
            wget https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/X86/tuic-server-1.0.0-x86_64-unknown-linux-gnu -O tuic-server
            ;;
        *)
            echo "不支持的架构。"
            return 1
            ;;
    esac

    chmod +x tuic-server

    curl -o bing.crt https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/ARM/bing.crt
    curl -o bing.key https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/ARM/bing.key

    curl -o config.json https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/ARM/config.json

    curl -o /lib/systemd/system/tuic.service https://gitlab.com/jinhuaitao66/tuicv5/-/raw/main/ARM/tuic.service

    systemctl enable --now tuic.service
    systemctl restart tuic
    systemctl status tuic | tail -n 20

    return_to_script
}

# 函数：卸载 TuiC
uninstall_tuic() {
    echo "开始卸载 TuiC..."
    systemctl stop tuic
    systemctl disable tuic
    rm /lib/systemd/system/tuic.service
    rm -rf /opt/tuic
    systemctl daemon-reload
    echo "TuiC 卸载完成。"
    return_to_script
}

# 函数：安装 HY2
install_hy2() {
    echo "开始安装 HY2..."
    # 提示用户选择架构
    echo "请选择要安装的架构："
    echo "1. AMD64 (x86_64)"
    echo "2. ARM64 (aarch64)"
    read -p "输入数字选择架构: " choice

    case $choice in
    1)
        ARCH="amd64"
        ;;
    2)
        ARCH="arm64"
        ;;
    *)
        echo "无效的选择，退出。"
        exit 1
        ;;
    esac

    # 下载 hysteria 可执行文件
    wget "https://gitlab.com/jinhuaitao66/hy2/-/raw/main/hysteria-linux-$ARCH" -O /usr/local/bin/hysteria

    # 设置 hysteria 可执行文件为可执行权限
    chmod +x /usr/local/bin/hysteria

    # 创建 hysteria 配置文件目录
    mkdir -p /etc/hysteria

    # 提示用户选择是否使用默认端口号和密码
    read -p "是否使用默认端口号和密码？[Y/n]: " default_choice
    default_choice=${default_choice:-Y}

    if [ $default_choice != "Y" ]; then
        # 提示用户输入端口号
        read -p "输入端口号: " port
    else
        port="23456"
        password="ziIDRbRQF6vG"
    fi

    if [ $default_choice != "Y" ]; then
        # 提示用户输入密码
        read -p "输入密码: " password
    fi

    # 创建 hysteria 配置文件
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port 

tls:
  cert: /etc/hysteria/bing.crt 
  key: /etc/hysteria/bing.key 

auth:
  type: password
  password: $password

masquerade: 
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true
EOF
    # 下载证书和密钥文件
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/hysteria/bing.key -out /etc/hysteria/bing.crt -subj "/CN=bing.com" -days 36500

    # 创建 systemd 服务单元文件
    cat << EOF > /etc/systemd/system/hysteria-server.service
[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=~
User=root
Group=root
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

EOF
# 创建 systemd 服务单元文件
    cat << EOF > /etc/systemd/system/hysteria-server@.service
[Unit]
Description=Hysteria Server Service (config.ylml)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=~
User=root
Group=root
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

EOF

    systemctl daemon-reload
    systemctl start hysteria-server.service
    systemctl enable hysteria-server.service
    systemctl status hysteria-server.service | tail -n 20

    return_to_script
}

# 函数：安装 XRAY
install_xray() {
    read -p "请选择配置选项 (1: VLESS+Reality, 2: Vmess+WS): " config_choice
    read -p "请输入端口选项 (1: 默认端口 23456, 2: 自定义端口): " port_choice

    case $port_choice in
        1)
            port=23456
            echo "使用默认端口 23456"
            ;;
        2)
            read -p "请输入自定义端口: " custom_port
            port=${custom_port:-23456}
            echo "使用自定义端口 $port"
            ;;
        *)
            echo "无效的选项，使用默认端口 23456"
            port=23456
            ;;
    esac

    echo "开始安装 XRAY..."
    bash -c "$(curl -L https://jht126.eu.org/https://github.com/jinhuaitao/Xray-install/blob/main/install-release.sh)" @ install -u root 

    if [ "$config_choice" -eq 1 ]; then
        cat << EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "0.0.0.0",
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "11aa87ba-9416-4cb3-9695-b693bbb2a351",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.jinhuaitao.eu.org:443",
                    "xver": 0,
                    "serverNames": [
                        "www.jinhuaitao.eu.org"
                    ],
                    "privateKey": "aLqiW8tbRezwFsth3ZWGDz3yCbLf1bUvdN-8D3HRn18",
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
                    "shortIds": [
                        "e41a7aa18a5db34a"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "policy": {
        "levels": {
            "0": {
                "handshake": 3,
                "connIdle": 180
            }
        }
    }
}
EOF
    elif [ "$config_choice" -eq 2 ]; then
        cat << EOF > /usr/local/etc/xray/config.json
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "11aa87ba-9416-4cb3-9695-b693bbb2a351",
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/?ed=2048"
                },
                "security": "none"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
    else
        echo "无效的配置选项"
        return
    fi

    systemctl restart xray
    systemctl status xray | tail -n 20

    return_to_script
}

# 函数：安装Apline版本XRAY
install_alpine_xray() {

#!/usr/bin/env bash

set -euxo pipefail

# 识别系统架构
case "$(uname -m)" in
    'i386' | 'i686') MACHINE='32' ;;
    'amd64' | 'x86_64') MACHINE='64' ;;
    'armv5tel') MACHINE='arm32-v5' ;;
    'armv6l') MACHINE='arm32-v6' ; grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5' ;;
    'armv7' | 'armv7l') MACHINE='arm32-v7a' ; grep Features /proc/cpuinfo | grep -qw 'vfp' || MACHINE='arm32-v5' ;;
    'armv8' | 'aarch64') MACHINE='arm64-v8a' ;;
    'mips') MACHINE='mips32' ;;
    'mipsle') MACHINE='mips32le' ;;
    'mips64') MACHINE='mips64' ;;
    'mips64le') MACHINE='mips64le' ;;
    'ppc64') MACHINE='ppc64' ;;
    'ppc64le') MACHINE='ppc64le' ;;
    'riscv64') MACHINE='riscv64' ;;
    's390x') MACHINE='s390x' ;;
    *) echo "不支持的架构"; exit 1 ;;
esac

TMP_DIRECTORY="$(mktemp -d)/"
ZIP_FILE="${TMP_DIRECTORY}Xray-linux-$MACHINE.zip"
DOWNLOAD_LINK="https://jht126.eu.org/https://github.com/XTLS/Xray-core/releases/download/v25.4.30/Xray-linux-$MACHINE.zip"

# 安装 curl 和 unzip（如果缺失）
apk update
apk add curl unzip

# 下载并验证
curl -L -o "$ZIP_FILE" "$DOWNLOAD_LINK"
curl -L -o "$ZIP_FILE.dgst" "$DOWNLOAD_LINK.dgst"

CHECKSUM=$(awk -F '= ' '/256=/ {print $2}' "$ZIP_FILE.dgst")
LOCALSUM=$(sha256sum "$ZIP_FILE" | awk '{print $1}')
[[ "$CHECKSUM" == "$LOCALSUM" ]] || { echo "SHA256 校验失败"; exit 1; }

# 解压
unzip -q "$ZIP_FILE" -d "$TMP_DIRECTORY"

# 安装核心文件
install -m 755 "${TMP_DIRECTORY}xray" "/usr/local/bin/xray"
install -d /usr/local/lib/xray/
install -m 755 "${TMP_DIRECTORY}geoip.dat" "/usr/local/lib/xray/geoip.dat"
install -m 755 "${TMP_DIRECTORY}geosite.dat" "/usr/local/lib/xray/geosite.dat"

# 安装默认配置文件
mkdir -p /usr/local/etc/xray
cat << EOF > /usr/local/etc/xray/config.json
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [{
    "port": 23456,
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "11aa87ba-9416-4cb3-9695-b693bbb2a351",
        "flow": "xtls-rprx-vision"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "dest": "www.jinhuaitao.eu.org:443",
        "serverNames": ["www.jinhuaitao.eu.org"],
        "privateKey": "aLqiW8tbRezwFsth3ZWGDz3yCbLf1bUvdN-8D3HRn18",
        "shortIds": ["e41a7aa18a5db34a"]
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls", "quic"]
    }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }, {
    "protocol": "blackhole",
    "tag": "block"
  }]
}
EOF

# 日志目录
mkdir -p /var/log/xray/
touch /var/log/xray/access.log /var/log/xray/error.log
chown -R nobody:nobody /var/log/xray

# 创建 OpenRC 启动脚本
cat << 'EOF' > /etc/init.d/xray
#!/sbin/openrc-run

description="Xray Service"

command="/usr/local/bin/xray"
command_args="-config /usr/local/etc/xray/config.json"
pidfile="/run/xray.pid"
command_background=true
EOF

chmod +x /etc/init.d/xray

# 注册并启动服务
rc-update add xray default
rc-service xray start

# 清理
rm -rf "$TMP_DIRECTORY"

echo "✅ 安装完成，Xray 已启动"


    return_to_script
}

# 函数：卸载 HY2
uninstall_hy2() {
    echo "开始卸载 HY2..."
    systemctl stop hysteria-server.service
    systemctl disable hysteria-server.service
    bash <(curl -fsSL https://get.hy2.sh/) --remove
    rm -rf /etc/hysteria
    echo "HY2 卸载完成。"
    return_to_script
}

# 函数：卸载 XRAY
uninstall_xray() {
    echo "开始卸载 XRAY..."
    bash -c "$(curl -L https://jht126.eu.org/https://github.com/jinhuaitao/Xray-install/blob/main/install-release.sh)" @ remove
    echo "XRAY 卸载完成。"
    return_to_script
}

# 函数：启动系统
reboot_system() {
    echo "正在重新启动系统..."
    reboot
}

# 函数：Debian 12系统安装
install_debian_12() {
    echo "请选择要安装的系统:"
    echo "1) Debian 13"
    echo "2) Ubuntu 22.04"
    echo "3) Alpine 3.22"
    read -p "请输入选项 (1, 2, 或 3): " choice
    
    case $choice in
        1)
            echo "正在安装 Debian 13系统..."
            curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O reinstall.sh $_ && bash reinstall.sh debian 13 --password Lili900508@@
            echo "Debian 13系统安装完成。"
            ;;
        3)
            echo "正在安装 Alpine 3.22系统..."
            curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O reinstall.sh $_ && bash reinstall.sh alpine 3.22 --password Lili900508@@
            echo "Alpine 3.22系统安装完成。"
            ;;
        2)
            echo "正在安装 Ubuntu 22.04系统..."
            bash <(curl -sSL https://gitlab.com/jinhuaitao66/jht/-/raw/main/InstallNET.sh) -ubuntu 22.04 -pwd 'Lili900508@@' --nomemcheck --network "static"
            echo "Ubuntu 22.04系统安装完成。"
            ;;
        *)
            echo "无效的选项。请重新运行脚本并选择有效的选项。"
            return 1
            ;;
    esac

    echo "正在重启机器..."
    reboot
    return_to_script
}


# 函数：安装 DOCKER
install_docker() {
    echo "开始安装 DOCKER..."
    curl -fsSL https://get.docker.com | sh
    ln -s /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin
    echo "Docker 安装完成。"
    return_to_script
}
install_xui() {
    echo "开始安装 XUI..."
    #!/bin/bash

# Function to install x-ui for AMD version
install_xui_amd() {
    echo "Installing x-ui (AMD version)..."
    curl -o /root/x-ui-linux-amd64.tar.gz https://gitlab.com/jinhuaitao66/xui/-/raw/main/x-ui-linux-amd64.tar.gz
    cd /root/
    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
    tar zxvf x-ui-linux-amd64.tar.gz
    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
    cp x-ui/x-ui.sh /usr/bin/x-ui
    cp -f x-ui/x-ui.service /etc/systemd/system/
    mv x-ui/ /usr/local/
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl restart x-ui
    echo "x-ui (AMD version) installation completed!"
}

# Function to install x-ui for ARM version
install_xui_arm() {
    echo "Installing x-ui (ARM version)..."
    curl -o /root/x-ui-linux-arm.tar.gz https://gitlab.com/jinhuaitao66/xui/-/raw/main/x-ui-linux-arm64.tar.gz
    cd /root/
    rm -rf x-ui/ /usr/local/x-ui/ /usr/bin/x-ui
    tar zxvf x-ui-linux-arm64.tar.gz
    chmod +x x-ui/x-ui x-ui/bin/xray-linux-* x-ui/x-ui.sh
    cp x-ui/x-ui.sh /usr/bin/x-ui
    cp -f x-ui/x-ui.service /etc/systemd/system/
    mv x-ui/ /usr/local/
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl restart x-ui
    echo "x-ui (ARM version) installation completed!"
}

# User input to choose version
echo "Please select the version to install:"
echo "1. AMD 版本"
echo "2. ARM 版本"
read -p "Enter your choice (1 or 2): " choice

if [ "$choice" -eq 1 ]; then
    install_xui_amd
elif [ "$choice" -eq 2 ]; then
    install_xui_arm
else
    echo "Invalid choice, exiting script."
    exit 1
fi

    echo "XUI 安装完成。"
    return_to_script
}
# 函数：安装 哪吒面板
install_nezha_panel() {
    echo "开始安装 哪吒面板..."
    curl -L https://gitlab.com/jinhuaitao66/nezha/-/raw/main/nezha.sh -o nezha.sh && chmod +x nezha.sh && sudo ./nezha.sh
    echo "哪吒面板安装完成。"
    return_to_script
}
# 函数：安装 Halo
install_Halo_panel() {
    echo "开始安装 Halo..."
    docker run -it -d --name halo --restart always -p 8090:8090 -v /mnt/data/halo/.halo2:/root/.halo2 jhtao.pp.ua/halohub/halo:2.21
    echo "Halo安装完成。"
    return_to_script
}
# 函数：安装 Alpine虚拟内存
install_alpine_ram() {
    echo "开始安装 Alpine虚拟内存..."
cd /etc/local.d
cat <<EOF > swap.start
#!/bin/sh

if [ ! -f /swapfile ]; then
  echo "Creating 4GB swapfile..."
  dd if=/dev/zero of=/swapfile bs=1M count=4096
  chmod 600 /swapfile
  mkswap /swapfile
fi

echo "Enabling swapfile..."
swapon /swapfile

EOF

# Step 启动 Alpine虚拟内存
    sudo chmod +x /etc/local.d/swap.start
    sudo rc-update add local default
    echo "Alpine虚拟内存安装完成。"
    return_to_script
}
# 函数：安装 AlpineHY2端口跳跃
install_alpine_hy2-port() {
    echo "开始安装 Alpine HY2端口跳跃..."

# 安装 iptables
sudo apk add iptables

# 使用 cat 创建 /etc/local.d/firewall.start 文件
cat <<EOF > /etc/local.d/firewall.start
#!/bin/sh
iptables -t nat -A PREROUTING -i eth0 -p udp --dport 20000:50000 -j REDIRECT --to-ports 23456
ip6tables -t nat -A PREROUTING -i eth0 -p udp --dport 20000:50000 -j REDIRECT --to-ports 23456
EOF

# 赋予可执行权限
sudo chmod +x /etc/local.d/firewall.start

# 添加 local 服务到启动项
sudo rc-update add local default

echo "Alpine HY2端口跳跃安装完成。"
    return_to_script
}
# 函数：nginxWebUI
install_nginx_WebUI() {
    echo "开始安装 nginxWebUI..."
    docker run -itd \
  -v /home/nginxWebUI:/home/nginxWebUI \
  -e BOOT_OPTIONS="--server.port=8080" \
  --net=host \
  --restart=always \
  jhtao.pp.ua/cym1102/nginxwebui:latest
    echo "nginxWebUI 安装完成。"
    return_to_script
}

# 函数：nexterm
install_nexterm() {
    echo "开始安装 nexterm..."
docker run -d -p 6989:6989 --name nexterm --restart always -v nexterm:/app/data jhtao.pp.ua/germannewsmaker/nexterm:1.0.2-OPEN-PREVIEW
    echo "nexterm 安装完成。"
    return_to_script
}

# 函数：oci-start
install_oci_start() {
#!/bin/bash

set -e

# 检测系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    SYSTEM=$ID
else
    echo "无法检测系统类型。请手动运行脚本。"
    exit 1
fi

# 根据系统类型安装 JDK
if [[ "$SYSTEM" == "debian" || "$SYSTEM" == "ubuntu" ]]; then
    echo "检测到系统为 Debian/Ubuntu，正在安装 default-jdk..."
    apt update && apt install -y default-jdk
elif [[ "$SYSTEM" == "alpine" ]]; then
    echo "检测到系统为 Alpine，正在安装 openjdk11..."
    apk update && apk add openjdk11
else
    echo "未支持的系统类型：$SYSTEM。请手动安装 JDK。"
    exit 1
fi

echo "JDK 安装完成。"

# 创建 oci-start 目录并进入
mkdir -p /root/oci-start && cd /root/oci-start

# 下载必要的文件
wget https://gitlab.com/jinhuaitao66/oci/-/raw/main/oci-start-release.jar
wget https://gitlab.com/jinhuaitao66/oci/-/raw/main/oci-start.yml
wget https://gitlab.com/jinhuaitao66/oci/-/raw/main/oci-start.sh

# 给 oci-start.sh 添加执行权限
chmod +x oci-start.sh

# 创建 OpenRC 服务文件
cat << 'EOF' > /etc/init.d/oci-start
#!/sbin/openrc-run

command="/root/oci-start/oci-start.sh"
command_args="start"
pidfile="/var/run/oci-start.pid"

depend() {
    need localmount
}

start_pre() {
    ebegin "Preparing to start oci"
    # 确保脚本可执行
    chmod +x $command
    eend $?
}

start() {
    ebegin "Starting oci"
    start-stop-daemon --start --pidfile $pidfile --make-pidfile --background --exec $command -- $command_args
    eend $?
}

stop() {
    ebegin "Stopping oci"
    start-stop-daemon --stop --pidfile $pidfile
    eend $?
}
EOF

# 给服务文件添加执行权限
chmod +x /etc/init.d/oci-start

# 添加服务到默认运行级别并重启服务
rc-update add oci-start default
rc-service oci-start restart

echo "OCI 服务已设置完成并已自动重启。"

    echo "oci-start 安装完成。"
    echo "访问地址：http://IP:9854"
    return_to_script
}

# 函数：mfa-start
install_mfa_start() {
#!/bin/bash

set -e

# 检测系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    SYSTEM=$ID
else
    echo "无法检测系统类型。请手动运行脚本。"
    exit 1
fi

# 根据系统类型安装 JDK
if [[ "$SYSTEM" == "debian" || "$SYSTEM" == "ubuntu" ]]; then
    echo "检测到系统为 Debian/Ubuntu，正在安装 default-jdk..."
    apt update && apt install -y default-jdk
elif [[ "$SYSTEM" == "alpine" ]]; then
    echo "检测到系统为 Alpine，正在安装 openjdk11..."
    apk update && apk add openjdk11
else
    echo "未支持的系统类型：$SYSTEM。请手动安装 JDK。"
    exit 1
fi

echo "JDK 安装完成。"

# 创建 mfa-start 目录并进入
mkdir -p /root/mfa-start && cd /root/mfa-start

# 下载必要的文件
wget https://gitlab.com/jinhuaitao66/mfa/-/raw/main/mfa-start-release.jar
wget https://gitlab.com/jinhuaitao66/mfa/-/raw/main/mfa-start.yml
wget https://gitlab.com/jinhuaitao66/mfa/-/raw/main/mfa-start.sh

# 给 mfa-start.sh 添加执行权限
chmod +x mfa-start.sh

# 创建 OpenRC 服务文件
cat << 'EOF' > /etc/init.d/mfa-start
#!/sbin/openrc-run

command="/root/mfa-start/mfa-start.sh"
command_args="start"
pidfile="/var/run/mfa-start.pid"

depend() {
    need localmount
}

start_pre() {
    ebegin "Preparing to start mfa"
    # 确保脚本可执行
    chmod +x $command
    eend $?
}

start() {
    ebegin "Starting mfa"
    start-stop-daemon --start --pidfile $pidfile --make-pidfile --background --exec $command -- $command_args
    eend $?
}

stop() {
    ebegin "Stopping mfa"
    start-stop-daemon --stop --pidfile $pidfile
    eend $?
}
EOF

# 给服务文件添加执行权限
chmod +x /etc/init.d/mfa-start

# 添加服务到默认运行级别并重启服务
rc-update add mfa-start default
rc-service mfa-start restart

echo "mfa 服务已设置完成并已自动重启。"

    echo "mfa-start 安装完成。"
    echo "访问地址：http://IP:9087 用户名:jht@jht.one 密码:Lili900508@@"
    return_to_script
}

# 函数：卸载 TuiC
install_x_ui() {
    echo "开始卸载 TuiC..."
    systemctl stop tuic
    systemctl disable tuic
    rm /lib/systemd/system/tuic.service
    rm -rf /opt/tuic
    systemctl daemon-reload
    echo "TuiC 卸载完成。"
    return_to_script
}


# 函数：安装 Linux 一键虚拟内存
install_linux_swap() {
    echo "正在下载并执行 Linux 一键虚拟内存脚本..."
    wget https://www.moerats.com/usr/shell/swap.sh && bash swap.sh
    echo "Linux 一键虚拟内存脚本执行完成。"
    return_to_script
}

# 函数：安装流量限制
install_traffic_limit() {
    echo "正在安装流量限制..."
    curl -sS -O https://gitlab.com/jinhuaitao66/network/-/raw/main/monthly_network_monitor.sh && chmod +x monthly_network_monitor.sh && ./monthly_network_monitor.sh
    echo "流量限制安装完成。"
    return_to_script
}


# 函数：修改密码
change_password() {
    echo "正在修改密码..."
    echo "root:Lili900508@@" | chpasswd
    echo "密码修改完成。"
    return_to_script
}


# 函数：安装it-tools
install_it_tools() {
    echo "正在安装it-tools..."
    docker run -d --name it-tools --restart unless-stopped -p 7090:80 jhtao.pp.ua/corentinth/it-tools:latest
    echo "it-tools安装完成。"
    return_to_script
}

# 函数：安装Webssh
install_web_ssh() {
    echo "正在安装Webssh..."
    docker run -d --net=host --log-driver json-file --log-opt max-file=1 --log-opt max-size=100m --restart always --name webssh -e authInfo='jht@jht.one:Lili900508@@' -e TZ=Asia/Shanghai jhtao.pp.ua/jrohy/webssh
    echo "Webssh安装完成。"
    return_to_script
}

# 函数：安装TCP Brutal
install_tcp_brutall() {
    echo "正在安装TCP Brutal..."
    bash <(curl -fsSL https://tcp.hy2.sh/)
    echo "TCP Brutal安装完成。"
    return_to_script
}

# 函数：安装MyIP
install_my_ip() {
    echo "正在安装MyIP..."
    docker run -d -p 18966:18966 --name myip --restart always jhtao.pp.ua/jason5ng32/myip:latest
    echo "MyIP安装完成。"
    return_to_script
}

# 函数：安装MyIP
install_san_huicheng() {
    echo "正在测试三网回程..."
    wget -qO- git.io/besttrace | bash
    echo "三网回程测试完成。"
    return_to_script
}

# 函数：安装 1Panel 
install_1_panel() {
    echo "正在下载并执行 1Panel..."
    curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && bash quick_start.sh
    echo "1Panel执行完成。"
    return_to_script
}

# 函数：安装 nginx-proxy-manager 
install_nginx_proxy() {
    mkdir -p /srv/nginx-proxy-manager
cd /srv/nginx-proxy-manager

cat <<EOF > docker-compose.yml
version: '3'
services:
  nginx-proxy-manager:
    image: 'jhtao.pp.ua/jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
EOF

# Step 5: 启动 Nginx Proxy Manager
docker-compose up -d

# 输出默认的登录信息
echo ""
echo "===================================="
echo "      默认登录信息"
echo "===================================="
echo ""
echo "   电子邮件: admin@example.com"
echo "   密码:     changeme"
echo ""
echo "===================================="
    return_to_script
}

# 函数：安装 Stirling PDF 
install_stirling_pdf() {
    mkdir -p /mnt/pdf
    cd /mnt/pdf || { echo "Failed to navigate to /mnt/pdf"; exit 1; }

    # 创建 docker-compose.yml 文件
    cat <<EOF > docker-compose.yml
version: '3.3'
services:
  stirling-pdf:
    image: jhtao.pp.ua/stirlingtools/stirling-pdf:latest
    ports:
      - '8080:8080'
    volumes:
      - ./trainingData:/usr/share/tessdata # Required for extra OCR languages
      - ./extraConfigs:/configs
      # - ./customFiles:/customFiles/
      # - ./logs:/logs/
    environment:
      - DOCKER_ENABLE_SECURITY=false
      - INSTALL_BOOK_AND_ADVANCED_HTML_OPS=false
      - LANGS=en_GB
    restart: unless-stopped
EOF
docker-compose up -d
#
    return_to_script
}

# 函数：安装 LibreTV 
install_libre_tv() {
    mkdir -p /mnt/libretv
    cd /mnt/libretv || { echo "Failed to navigate to /mnt/pdf"; exit 1; }

    # 创建 docker-compose.yml 文件
    cat <<EOF > docker-compose.yml
version: '3.3'
services:
  libretv:
    image: bestzwei/libretv:latest
    container_name: libretv
    ports:
      - "8899:8080" # 将内部 8080 端口映射到主机的 8899 端口
    environment:
      - PASSWORD=${PASSWORD:-900508} 
    restart: unless-stopped
EOF
docker-compose up -d
#
    return_to_script
}


# 函数：安装 MEMOS 
install_me_mos() {
    echo "正在下载并执行 MEMOS..."
    docker run -d --name memos --restart=always -p 5230:5230 -v /mnt/data/memos/.memos/:/var/opt/memos jhtao.pp.ua/neosmemo/memos:stable
    echo "MEMOS安装完成。"
    return_to_script
}

# 函数：安装 DDNS-GO
install_ddns_go() {
    echo "正在下载并执行 DDNS-GO..."
    docker run -d --name ddns-go --restart=always --net=host -v /opt/ddns-go:/root jeessy/ddns-go
    docker exec ddns-go ./ddns-go -resetPassword Lili900508@@
    docker restart ddns-go
    echo "DDNS-GO安装完成。"
    return_to_script
}

# 函数：安装 Vaultwarden
install_vault_warden() {
    echo "正在下载并执行 Vaultwarden..."
        mkdir -p /mnt/Vaultwarden
    cd /mnt/Vaultwarden || { echo "Failed to navigate to /mnt/pdf"; exit 1; }

docker pull vaultwarden/server:latest
docker run --detach --name vaultwarden \
  --env DOMAIN="https://vw.domain.tld" \
  --volume /vw-data/:/data/ \
  --restart unless-stopped \
  --publish 3003:80 \
  jhtao.pp.ua/vaultwarden/server:latest
docker-compose up -d
#
    return_to_script
    echo "Vaultwarden安装完成。"
    return_to_script
}

# 函数：安装 Alist
install_ali_st() {
    echo "正在下载并执行 Alist..."
mkdir -p /mnt/alist
docker run -d --restart=unless-stopped -v /etc/alist:/mnt/alist/data -p 5244:5244 -e PUID=0 -e PGID=0 -e UMASK=022 --name="alist" jhtao.pp.ua/xhofe/alist:latest
    echo "设置 Alist 管理员密码..."
    docker exec alist ./alist admin set Lili900508@@
    echo "Alist安装完成。"
    return_to_script
}


# 函数：安装 网络优化 
install_network_fix() {
    echo "正在进行网络优化..."
    for pkg in ntpdate htpdate; do
    if ! command -v $pkg &> /dev/null; then
        apt install $pkg -y
    fi
done

timedatectl set-timezone Asia/Shanghai

timeout 5 ntpdate time1.google.com || timeout 5 htpdate -s www.baidu.com
hwclock -w

entropy=$(< /proc/sys/kernel/random/entropy_avail)
if [ $entropy -lt "1000" ] && ! systemctl is-active --quiet haveged; then
    apt install haveged -y
    systemctl enable haveged
    systemctl restart haveged
fi

echo "1048576" > /proc/sys/fs/file-max
ulimit -n 1048576

chattr -i /etc/sysctl.conf
cat > /etc/sysctl.conf << EOF
# Memory usage
# https://blog.cloudflare.com/the-story-of-one-latency-spike/
# https://cloud.google.com/architecture/tcp-optimization-for-network-performance-in-gcp-and-hybrid/
# https://zhensheng.im/2021/01/31/linux-wmem-and-rmem-adjustments.meow
# https://github.com/redhat-performance/tuned/blob/master/profiles/network-throughput/tuned.conf
# ReceiveBuffer: X - (X / (2 ^ tcp_adv_win_scale)) = RTT * Bandwidth / 8
# SendBuffer: RTT * Bandwidth / 8 * 0.7
net.core.netdev_max_backlog = 262144
net.ipv4.tcp_max_syn_backlog = 8192
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 16384 131072 67108864
net.ipv4.tcp_wmem = 4096 16384 33554432
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072

# Layer 2
# No Proxy ARP, obviously
net.ipv4.conf.default.proxy_arp = 0
net.ipv4.conf.all.proxy_arp = 0
# Do not reply ARP requests if the target IP address is not configured on the incoming interface
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.all.arp_ignore = 1
# When sending ARP requests, use the best IP address configured on the outgoing interface
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_announce = 2
# Enable gratuitous arp requests
net.ipv4.conf.default.arp_notify = 1
net.ipv4.conf.all.arp_notify = 1

# IPv4 routing
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.send_redirects = 0
# Enable when there are 1-2K hosts
net.ipv4.neigh.default.gc_thresh1 = 2048
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192

# IPv6 routing
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
# Enable when there are 1-2K hosts
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384

# PMTUD
# https://blog.cloudflare.com/path-mtu-discovery-in-practice/
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024

# MPLS & L3VPN support
# https://web.archive.org/web/20210301222346/https://cumulusnetworks.com/blog/vrf-for-linux/
# net.mpls.ip_ttl_propagate = 1
# net.mpls.default_ttl = 255
# net.mpls.platform_labels = 1048575
net.ipv4.tcp_l3mdev_accept = 0
net.ipv4.udp_l3mdev_accept = 0
net.ipv4.raw_l3mdev_accept = 0
# net.mpls.conf.lo.input = 1

# ICMP
# net.ipv4.icmp_errors_use_inbound_ifaddr = 1
# net.ipv4.icmp_ratelimit = 0
# net.ipv6.icmp.ratelimit = 0
net.ipv4.icmp_echo_ignore_all = 1
# net.ipv6.icmp_echo_ignore_all = 1

# TCP connection accepting
# https://serverfault.com/questions/518862/will-increasing-net-core-somaxconn-make-a-difference
net.core.somaxconn = 8192
net.ipv4.tcp_abort_on_overflow = 0

# TCP connection recycling
# https://dropbox.tech/infrastructure/optimizing-web-servers-for-high-throughput-and-low-latency
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_tw_buckets = 4096

# TCP congestion control
# https://blog.cloudflare.com/http-2-prioritization-with-nginx/
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_window_scaling = 1

# TCP keepalive
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# TCP auxiliary
# https://dropbox.tech/infrastructure/optimizing-web-servers-for-high-throughput-and-low-latency
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_adv_win_scale = 1

# ECN
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_ecn_fallback = 1

# ECMP hashing
# https://web.archive.org/web/20210204031636/https://cumulusnetworks.com/blog/celebrating-ecmp-part-two/
net.ipv4.fib_multipath_hash_policy = 1
net.ipv4.fib_multipath_use_neigh = 1

# GRE keepalive
# https://blog.artech.se/2016/01/10/4/
net.ipv4.conf.default.accept_local = 1
net.ipv4.conf.all.accept_local = 1

# IGMP
# https://phabricator.vyos.net/T863
net.ipv4.igmp_max_memberships = 512

# IPv6 route table size bug fix
# https://web.archive.org/web/20200516030405/https://lists.nat.moe/pipermail/transit-service/2020-May/000000.html
net.ipv6.route.max_size = 2147483647

# Prefer different parity for ip_local_port_range start and end value
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 8080

# Maximum number of open files
fs.file-max = 1048576

# Avoid the use of swap spaces where possible
vm.swappiness = 1
EOF
sysctl -p

cat > /etc/security/limits.conf << EOF
root     hard   nofile    1048576
root     soft   nproc     1048576
root     hard   nproc     1048576
root     soft   core      1048576
root     hard   core      1048576
root     hard   memlock   unlimited
root     soft   memlock   unlimited

*     soft   nofile    1048576
*     hard   nofile    1048576
*     soft   nproc     1048576
*     hard   nproc     1048576
*     soft   core      1048576
*     hard   core      1048576
*     hard   memlock   unlimited
*     soft   memlock   unlimited
EOF
    echo "网络优化完成。"
    return_to_script
}
# 函数：安装MTG通知
install_bot_tg() {
    # 检查是否已经安装过
    if [ ! -f "/var/tmp/bot_tg_installed.flag" ]; then
        echo "正在安装TG流量通知..."
        # 更新软件包并安装所需软件包
        apt update && apt install -y python3 python3-pip python3-requests python3-schedule
        # 创建标志文件，表示已经安装过
        touch /var/tmp/bot_tg_installed.flag
    fi
    
    # 下载并设置脚本
    curl -sS -O https://gitlab.com/jinhuaitao66/network/-/raw/main/bot.py && chmod +x bot.py && python3 ./bot.py
    echo "TG流量通知安装完成。"

    return_to_script
}
# 函数：安装Sun-panel
install_Sun_panel() {
    docker run -d --restart=always -p 3002:3002 \
-v /mnt/data/sun-panel/conf:/app/conf \
-v /var/run/docker.sock:/var/run/docker.sock \
--name sun-panel \
jhtao.pp.ua/hslr/sun-panel:latest

    return_to_script
}
# 函数：安装Alpine版docker
install_alpine_docker() {
    apk add docker docker-compose
    service docker start
    rc-update add docker boot
    return_to_script
}
# 函数：安装Alpine版Webtop
install_alpine_webtop() {
docker run -d \
--name=webtop \
--security-opt seccomp=unconfined \
-e PUID=1000 \
-e PGID=1000 \
-e TZ=Etc/UTC \
-e SUBFOLDER=/ \
-e TITLE=Webtop \
-e LC_ALL=zh_CN.UTF-8 \
-e DOCKER_MODS=linuxserver/mods:universal-package-install \
-e INSTALL_PACKAGES=font-noto-cjk \
-p 3080:3000 \
-v /home/docker/webtop/data:/config \
-v /var/run/docker.sock:/var/run/docker.sock \
--device /dev/dri:/dev/dri \
--shm-size="1gb" \
--restart unless-stopped \
jhtao.pp.ua/lscr.io/linuxserver/webtop:latest

return_to_script
}
# 函数：安装甲骨文保活
install_Oracle_Cloud() {
# 下载并运行 安装甲骨文保活 脚本
cd /root
wget -qO memory_usage.sh https://raw.githubusercontent.com/Mrmineduce21/Oracle_OneKey_Active/main/memory_usage.sh
chmod +x memory_usage.sh
bash memory_usage.sh consume 2G
return_to_script
}
# 函数：挂载甲骨文附加卷
install_Oracle_disk() {
#!/bin/bash

VG_NAME="myvg"
LV_NAME="mylv"
MOUNT_POINT="/mnt/bigdisk"

echo "🛠️ 安装 lvm2 和 blkid 工具..."
apk add --no-cache lvm2 util-linux

echo "🚀 启动 LVM 服务..."
rc-update add lvm boot
service lvm start || echo "⚠️ LVM 服务未成功启动，但继续执行初始化"

# 获取所有非 /dev/sda 的磁盘
CANDIDATES=($(lsblk -dno NAME | grep -v "^sda"))
echo "🧨 以下磁盘将被完全清空并合并为 LVM："
for dev in "${CANDIDATES[@]}"; do
  echo "  - /dev/$dev"
done

# 确认提示
read -rp "⚠️ 确认要继续吗？这将清除以上所有磁盘数据（yes/no）: " answer
if [[ "$answer" != "yes" ]]; then
  echo "❌ 已取消操作。"
  exit 0
fi

# 开始处理
DISKS=()
for dev in "${CANDIDATES[@]}"; do
  path="/dev/$dev"
  echo "🧨 清理磁盘 $path..."
  umount ${path}* 2>/dev/null
  vgchange -an || true
  wipefs -a "$path"
  dd if=/dev/zero of="$path" bs=1M count=10 status=none
  pvremove -ff "$path" 2>/dev/null
  DISKS+=("$path")
done

if [ ${#DISKS[@]} -eq 0 ]; then
  echo "❌ 没有找到可用磁盘"
  exit 1
fi

echo "✅ 已清理并准备的磁盘: ${DISKS[@]}"

# 创建物理卷
echo "📦 创建物理卷..."
for disk in "${DISKS[@]}"; do
  pvcreate "$disk" || exit 1
done

# 创建卷组
echo "🧱 创建卷组 $VG_NAME..."
vgcreate "$VG_NAME" "${DISKS[@]}" || exit 1

# 创建逻辑卷
echo "📏 创建逻辑卷 $LV_NAME..."
lvcreate -l 100%FREE -n "$LV_NAME" "$VG_NAME" || exit 1

# 格式化
echo "🧹 格式化为 ext4..."
mkfs.ext4 "/dev/$VG_NAME/$LV_NAME" || exit 1

# 挂载
echo "📂 挂载到 $MOUNT_POINT..."
mkdir -p "$MOUNT_POINT"
mount "/dev/$VG_NAME/$LV_NAME" "$MOUNT_POINT" || exit 1

# 添加到 /etc/fstab
UUID=$(blkid -s UUID -o value "/dev/$VG_NAME/$LV_NAME")
echo "🔗 添加到 /etc/fstab..."
echo "UUID=$UUID $MOUNT_POINT ext4 defaults 0 2" >> /etc/fstab

echo "✅ 完成：${#DISKS[@]} 个磁盘已合并并挂载到 $MOUNT_POINT"





return_to_script
}
# 函数：NodeQuality测试脚本
install_Node_Quality() {
echo "正在执行融合怪测试..."
bash <(curl -sL https://run.NodeQuality.com) 
return_to_script
}

# 函数：安装DNS解锁
install_d_ns() {
# 下载并运行 安装DNS解锁
# 定义函数更新 resolv.conf
update_dns() {
  echo -e "$1" > /etc/resolv.conf
  echo "DNS 已切换到 $2"
}

# 提供选项
echo "请选择要切换的 DNS:"
echo "1) 解锁 HK 的 DNS"
echo "2) 解锁 SG 的 DNS"
echo "3) 恢复默认 的 DNS"
read -p "输入数字选择 (1/2/3): " choice

case $choice in
  1)
    hk_dns="nameserver 154.12.177.22\nnameserver 1.1.1.1\nnameserver 2001:4860:4860::1111\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::8888"
    update_dns "$hk_dns" "HK"
    ;;
  2)
    sg_dns="nameserver 157.20.104.47\nnameserver 1.1.1.1\nnameserver 2001:4860:4860::1111\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::8888"
    update_dns "$sg_dns" "SG"
    ;;
  3)
    cf_dns="nameserver 1.1.1.1\nnameserver 2001:4860:4860::1111\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::8888"
    update_dns "$cf_dns" "默认DNS"
    ;;
  *)
    echo "无效选择，退出脚本。"
    exit 1
    ;;
esac
return_to_script
}


# 函数：安装Alpine系统arm-hysteria2
install_alpine_hy2() {
# 安装所需软件包
    apk add wget curl git openssh openssl openrc

    # 生成密码
    GENPASS="ziIDRbRQF6vG"

    # 配置文件生成函数
    echo_hysteria_config_yaml() {
      cat << EOF
listen: :23456

#有域名，使用CA证书
#acme:
#  domains:
#    - test.heybro.bid #你的域名，需要先解析到服务器ip
#  email: xxx@gmail.com

#使用自签名证书
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: $GENPASS

masquerade:
  type: proxy
  proxy:
    url: https://bing.com/
    rewriteHost: true
EOF
    }

    # 自启动脚本生成函数
    echo_hysteria_autoStart(){
      cat << EOF
#!/sbin/openrc-run

name="hysteria"

command="/usr/local/bin/hysteria"
command_args="server --config /etc/hysteria/config.yaml"

pidfile="/var/run/${name}.pid"

command_background="yes"

depend() {
        need networking
}

EOF
    }

    # 提示用户选择架构版本
    echo "请选择要安装的架构版本:"
    echo "1) AMD版本"
    echo "2) ARM版本"
    read -p "输入选项 [1-2]: " choice

    # 根据选择设置下载链接
    case $choice in
        1)
            ARCH="amd64"
            DOWNLOAD_URL="https://download.hysteria.network/app/latest/hysteria-linux-amd64"
            ;;
        2)
            ARCH="arm64"
            DOWNLOAD_URL="https://download.hysteria.network/app/latest/hysteria-linux-arm64"
            ;;
        *)
            echo "无效选项，请重新运行脚本并选择 1 或 2。"
            exit 1
            ;;
    esac

    # 下载Hysteria
    wget -O /usr/local/bin/hysteria $DOWNLOAD_URL --no-check-certificate
    chmod +x /usr/local/bin/hysteria

    # 创建配置目录
    mkdir -p /etc/hysteria/

    # 生成自签名证书
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=bing.com" -days 36500

    # 写入配置文件
    echo_hysteria_config_yaml > "/etc/hysteria/config.yaml"

    # 写入自启动脚本
    echo_hysteria_autoStart > "/etc/init.d/hysteria"
    chmod +x /etc/init.d/hysteria

    # 启用自启动
    rc-update add hysteria

    # 启动服务
    service hysteria start

    # 输出安装信息
    echo "------------------------------------------------------------------------"
    echo "hysteria2已经安装完成"
    echo "默认端口： 23456 ， 密码为： $GENPASS ，工具中配置：tls，SNI为： bing.com"
    echo "配置文件：/etc/hysteria/config.yaml"
    echo "已经随系统自动启动"
    echo "看状态 service hysteria status"
    echo "重启 service hysteria restart"
    echo "请享用。"
    echo "------------------------------------------------------------------------"
    return_to_script
}
# 函数：返回脚本首页
return_to_script() {
    read -rp "操作已完成。是否返回脚本页面？[Y/n]: " choice
    case "$choice" in
        y|Y|"")
            exec "$0"
            ;;
        n|N)
            echo "感谢使用脚本！再见。"
            exit 0
            ;;
        *)
            echo "无效的选择。"
            return_to_script
            ;;
    esac
}

# 主菜单
while true; do
    clear
    echo "     欢   迎   使   用   J H T   脚    本"
    echo "============================================"
    echo "             ██╗██   ██╗████████╗         "
    echo "             ██║██   ██║╚══██╔══╝         "
    echo "             ██║███████║   ██║            "
    echo "        ██   ██║██╔══██║   ██║            "
    echo "        ╚█████╔╝██║  ██║   ██║            "
    echo "         ╚════╝ ╚═╝  ╚═╝   ╚═╝            "
    echo "============================================"
    echo "请选择要执行的操作:"
    echo "0. 退出脚本                    4. 启用 BBR 功能"     
    echo "1. 安装/卸载 TuiC 服务         5. 安装依赖软件包"   
    echo "2. 安装/卸载 HY2 服务          6. 常用工具"        
    echo "3. 安装/卸载 XRAY 服务         99. 重新启动系统"
    read -p "请输入数字选择操作 [0-99]: " choice

    case $choice in
        0)
            echo "退出脚本。"
            exit 0
            ;;
        1)
            echo "请选择要执行的操作:"
            echo "1. 安装 TuiC 服务"
            echo "2. 卸载 TuiC 服务"
            read -p "请输入数字选择操作 [1-2]: " tuic_choice
            case $tuic_choice in
                1)
                    install_tuic
                    ;;
                2)
                    uninstall_tuic
                    ;;
                *)
                    echo "无效的选择！"
                    ;;
            esac
            ;;
        2)
            echo "请选择要执行的操作:"
            echo "1. 安装 HY2 服务"
            echo "2. 卸载 HY2 服务"
            read -p "请输入数字选择操作 [1-2]: " hy2_choice
            case $hy2_choice in
                1)
                    install_hy2
                    ;;
                2)
                    uninstall_hy2
                    ;;
                *)
                    echo "无效的选择！"
                    ;;
            esac
            ;;
        3)
            echo "请选择要执行的操作:"
            echo "1. 安装 XRAY 服务"
            echo "2. 卸载 XRAY 服务"
            read -p "请输入数字选择操作 [1-2]: " xray_choice
            case $xray_choice in
                1)
                    install_xray
                    ;;
                2)
                    uninstall_xray
                    ;;
                *)
                    echo "无效的选择！"
                    ;;
            esac
            ;;
        4)
            enable_bbr
            ;;
        5)
            install_dependencies
            ;;
        6)
            echo "请选择要执行的操作:"
            echo "请选择要执行的操作:"
            echo "   1. DD系统安装                9. it-tools"
            echo "   2. NodeQuality测试脚本      10. WebSSH"
            echo "   3. DOCKER安装               11. 安装1Panel"
            echo "   4. 哪吒面板安装             12. TCP Brutal"
            echo "   5. X-UI 安装                13. MyIP"
            echo "   6. Linux一键虚拟内存        14. 三网回程测试"
            echo "   7. 流量限制                 15. TG流量通知"
            echo "   8. 修改密码                 16.网络优化" 
            echo "   17. Sun-panel               18.甲骨文ARM保活" 
            echo "   19. Alpine版工具            20.安装MEMOS" 
            echo "   21. Nginx Proxy Manager     22.安装Halo   " 
            echo "   23. DNS解锁                 24.NginxWebUI " 
            echo "   25. 安装Nexterm             26.OCI-START" 
            echo "   27. Stirling PDF            28.网页版验证" 
            echo "   29. DDNS-GO                 30.密码管理器" 
            echo "   31. Alist                   32.安装X-UI" 
            echo "   33. 挂载甲骨文附加卷        34.安装LibreTV" 
            read -p "请输入数字选择操作 [1-34]: " tool_choice
            case $tool_choice in
                1)
                    install_debian_12
                    ;;
                2)
                    install_Node_Quality                    
                    ;;
                3)
                    install_docker
                    ;;
                4)
                    install_nezha_panel
                    ;;
                5)
                    install_x_ui
                    ;;
                6)
                    install_linux_swap
                    ;;
                7)
                    install_traffic_limit
                    ;;
                8)
                    change_password
                    ;;
                9)
                    install_it_tools
                    ;;
                10)
                    install_web_ssh
                    ;;
                11)
                   install_1_panel
                   ;;
                12)
                   install_tcp_brutall
                   ;;
                13)
                   install_my_ip
                   ;;
                14)
                   install_san_huicheng
                   ;;
                15)
                   install_bot_tg
                   ;; 
                16)
                   install_network_fix
                   ;; 
                17)
                   install_Sun_panel
                   ;;
                18)
                   install_Oracle_Cloud
                   ;; 
                20)
                   install_me_mos
                   ;;
                21)
                   install_nginx_proxy
                   ;;
                22)
                   install_Halo_panel
                   ;;
                23)
                   install_d_ns
                   ;;
                24)
                   install_nginx_WebUI
                   ;;
                25)
                   install_nexterm
                   ;;
                26)
                   install_oci_start
                   ;;
                27)
                   install_stirling_pdf
                   ;;
                28)
                   install_mfa_start
                   ;;
                29)
                   install_ddns_go
                   ;;
                30)
                   install_vault_warden
                   ;;
                31)
                   install_ali_st
                   ;;
                32)
                   install_xui
                   ;;
                33)
                   install_Oracle_disk
                   ;;
                34)
                   install_libre_tv
                   ;;
                19)
                    echo "请选择要执行的操作:"
                    echo "请选择要执行的操作:"
                    echo "   1.Alpine版HY2               4.Alpine版Webtop" 
                    echo "   2.Alpine版xray              5.Alpine版虚拟内存"
                    echo "   3.Alpine版Docker            6.Alpine版HY2端口跳跃" 
                    read -p "请输入数字选择操作 [1-6]: " tool_choice
                    case $tool_choice in 
                        1)
                          install_alpine_hy2
                          ;;
                        2)
                          install_alpine_xray
                          ;;
                        3)
                          install_alpine_docker
                          ;;
                        4)
                          install_alpine_webtop
                          ;;
                        5)
                          install_alpine_ram
                          ;;
                        6)
                          install_alpine_hy2-port
                          ;;
                        *)
                          echo "无效的选择！"
                          ;;
                        esac
                        ;;
            esac
            ;;
        99)
            reboot_system
            ;;
        *)
            echo "无效的选择！"
            ;;
    esac
done
