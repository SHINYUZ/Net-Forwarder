#!/bin/bash

# ====================================================
#  转发脚本 Script v1.7.1 By Shinyuz
#  快捷键: zf
#  更新内容: 极致精简排版 + 智能源静默切换
# ====================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'
BLUE='\033[0;36m' 

# 路径定义
REALM_PATH="/usr/local/bin/realm"
REALM_CONFIG="/etc/realm/config.toml"
REALM_SERVICE="/etc/systemd/system/realm.service"
REMARK_FILE="/etc/realm/remarks.txt" 
SCRIPT_PATH=$(readlink -f "$0")
TRAFFIC_DIR="/etc/realm"
TG_CONF="$TRAFFIC_DIR/tg_notify.conf"
MONITOR_SERVICE="/etc/systemd/system/forwarding-traffic.service"
MONITOR_TIMER="/etc/systemd/system/forwarding-traffic.timer"
RESET_UNIT_DIR="/etc/systemd/system"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\n${RED}错误：请使用 root 用户运行此脚本！${PLAIN}\n"
        exit 1
    fi
}

check_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  REALM_ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64) REALM_ARCH="aarch64-unknown-linux-gnu" ;;
        *)       echo -e "\n${RED}不支持的架构: $ARCH${PLAIN}"; exit 1 ;;
    esac
}

set_shortcut() {
    if [ ! -f "/usr/bin/zf" ]; then
        ln -sf "$SCRIPT_PATH" /usr/bin/zf
        chmod +x /usr/bin/zf
        echo -e "${GREEN}快捷键 'zf' 已设置成功！以后输入 zf 即可打开面板。${PLAIN}"
    fi
}

enable_forwarding() {
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/ip_forward.conf
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/ip_forward.conf
    sysctl -p /etc/sysctl.d/ip_forward.conf >/dev/null 2>&1
}

check_status() {
    if systemctl is-active --quiet realm; then
        realm_status="${GREEN}running${PLAIN}"
    else
        realm_status="${RED}stopped${PLAIN}"
    fi

    if systemctl is-active --quiet netfilter-persistent || systemctl is-active --quiet iptables; then
        iptables_status="${GREEN}running${PLAIN}"
    else
        iptables_status="${RED}stopped${PLAIN}"
    fi
}

update_script() {
    echo -e "\n${YELLOW}正在检查更新...${PLAIN}"
    echo ""
    wget -N --no-check-certificate "https://raw.githubusercontent.com/Shinyuz/net-forwarder/main/forwarding.sh" && chmod +x forwarding.sh && ./forwarding.sh
    exit 0
}

init_remark_file() {
    mkdir -p /etc/realm
    if [ ! -f "$REMARK_FILE" ]; then
        touch "$REMARK_FILE"
    fi
}

get_realm_remark() {
    local port=$1
    local content=$(grep "^$port|" "$REMARK_FILE" | cut -d'|' -f2)
    if [ -z "$content" ]; then
        echo "无"
    else
        echo "$content"
    fi
}

set_realm_remark() {
    local port=$1
    local content=$2
    init_remark_file
    sed -i "/^$port|/d" "$REMARK_FILE"
    if [ -n "$content" ]; then
        echo "$port|$content" >> "$REMARK_FILE"
    fi
}

del_realm_remark() {
    local port=$1
    init_remark_file
    sed -i "/^$port|/d" "$REMARK_FILE"
}

get_latest_version() {
    local version=$(wget -qO- -T 3 -t 1 "https://api.github.com/repos/zhboner/realm/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
    if [ -z "$version" ]; then
        echo "v2.7.0"
    else
        echo "$version"
    fi
}

install_realm() {
    check_arch # 确保已定义 REALM_ARCH
    echo -e "\n${YELLOW}正在准备安装 realm...${PLAIN}"
    echo ""  # [空行]
    
    # 1. 智能版本检测与策略选择
    echo -e "正在检测网络环境与最新版本..."
    echo ""  # [空行]

    # 尝试获取在线版本
    ONLINE_VER=$(wget -qO- -T 3 -t 1 "https://api.github.com/repos/zhboner/realm/releases/latest" | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g')
    
    if [[ -n "$ONLINE_VER" ]]; then
        # 情况A: 成功获取 (IPv4/双栈)
        VERSION="$ONLINE_VER"
        echo -e "检测到最新版本: ${GREEN}${VERSION}${PLAIN}"
        echo ""  # [空行]
        echo -e "网络策略: ${GREEN}优先官方源${PLAIN}"
        echo ""  # [空行]
        USE_MIRROR_FIRST=false
    else
        # 情况B: 获取失败 (IPv6 Only)
        VERSION="v2.9.1" # Realm 的保底版本
        echo -e "${YELLOW}无法连接 GitHub API，切换至保底版本: ${VERSION}${PLAIN}"
        echo ""  # [空行]
        echo -e "网络策略: ${YELLOW}优先镜像源 (IPv6优化)${PLAIN}"
        echo ""  # [空行]
        USE_MIRROR_FIRST=true
    fi
    
    FILENAME="realm-$REALM_ARCH.tar.gz"
    URL_OFFICIAL="https://github.com/zhboner/realm/releases/download/$VERSION/$FILENAME"
    URL_MIRROR="https://gh-proxy.com/https://github.com/zhboner/realm/releases/download/$VERSION/$FILENAME"
    
    DOWNLOAD_SUCCESS=0

    # 2. 执行下载 (根据策略)
    if [[ "$USE_MIRROR_FIRST" == "true" ]]; then
        # === 策略B: 优先镜像 ===
        echo -e "正在下载..."
        echo ""  # [空行]
        wget -T 20 -t 2 -O realm.tar.gz "$URL_MIRROR"
        if [ $? -eq 0 ]; then
            DOWNLOAD_SUCCESS=1
        else
            echo -e "${YELLOW}镜像源失败，尝试官方源...${PLAIN}"
            wget -T 5 -t 1 -O realm.tar.gz "$URL_OFFICIAL"
            if [ $? -eq 0 ]; then DOWNLOAD_SUCCESS=1; fi
        fi
    else
        # === 策略A: 优先官方 ===
        echo -e "正在下载..."
        echo ""  # [空行]
        # 官方源允许静默尝试
        wget -T 10 -t 1 -O realm.tar.gz "$URL_OFFICIAL" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            DOWNLOAD_SUCCESS=1
        else
            echo -e "${YELLOW}官方源超时，自动切换镜像源...${PLAIN}"
            wget -T 15 -t 2 -O realm.tar.gz "$URL_MIRROR"
            if [ $? -eq 0 ]; then DOWNLOAD_SUCCESS=1; fi
        fi
    fi

    if [ $DOWNLOAD_SUCCESS -eq 0 ]; then
        echo "" 
        echo -e "${RED}下载失败！请检查网络连接。${PLAIN}"
        rm -f realm.tar.gz
        return
    fi
    
    # 3. 解压安装
    echo -e "${GREEN}下载成功，正在安装...${PLAIN}"
    
    tar -xvf realm.tar.gz > /dev/null 2>&1
    if [ ! -f "realm" ]; then
        echo -e "\n${RED}解压失败，未找到 realm 二进制文件！${PLAIN}\n"
        rm -f realm.tar.gz
        return
    fi

    mv realm $REALM_PATH
    chmod +x $REALM_PATH
    rm -f realm.tar.gz
    
    mkdir -p /etc/realm
    if [ ! -f "$REALM_CONFIG" ]; then
        cat > $REALM_CONFIG <<EOF
[dns]
mode = "ipv4_and_ipv6"
protocol = "tcp_and_udp"
nameservers = ["1.1.1.1:53", "1.0.0.1:53"]
min_ttl = 600
max_ttl = 3600
cache_size = 256

[network]
use_udp = true
zero_copy = true
fast_open = false
tcp_timeout = 300
udp_timeout = 30
send_proxy = false
send_proxy_version = 2
accept_proxy = false
accept_proxy_timeout = 5

EOF
    fi
    init_remark_file

    cat > $REALM_SERVICE <<EOF
[Unit]
Description=realm Forwarding Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
ExecStart=$REALM_PATH -c $REALM_CONFIG
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo ""
    systemctl enable realm
    echo ""
    echo -e "${GREEN}realm 安装完成！${PLAIN}"
    echo "" 
}

add_realm_rule() {
    echo -e "\n${YELLOW}添加 realm 转发规则${PLAIN}\n"

    read -p "请输入本地监听端口: " lport
    echo ""
    read -p "请输入目标 IP/域名: " rip
    echo ""
    read -p "请输入目标端口: " rport
    echo ""
    read -p "请输入备注名称: " remarks
    echo ""
    
    echo "请选择转发协议:"
    echo ""
    echo "1. TCP + UDP"
    echo ""
    echo "2. 仅 TCP"
    echo ""
    echo "3. 仅 UDP"
    echo ""
    read -p "请输入选项 [1-3 回车默认1]: " net_choice
    echo ""

    if [[ -z "$lport" || -z "$rip" || -z "$rport" ]]; then
        echo -e "${RED}输入不能为空！${PLAIN}"
        return
    fi

    if [ ! -s "$REALM_CONFIG" ] || ! grep -q "\[network\]" "$REALM_CONFIG"; then
        rebuild_realm_config
    fi
    
    config_block="[[endpoints]]\nlisten = \"[::]:$lport\"\nremote = \"$rip:$rport\""
    
    case "$net_choice" in
        2) 
            config_block="$config_block\nnetwork = \"tcp\"" 
            msg_proto="仅 TCP"
            ;;
        3) 
            config_block="$config_block\nnetwork = \"udp\"" 
            msg_proto="仅 UDP"
            ;;
        *) 
            config_block="$config_block\n# network = \"tcp+udp\"" 
            msg_proto="TCP + UDP"
            ;;
    esac

    echo -e "$config_block" >> $REALM_CONFIG
    
    if [ -n "$remarks" ]; then
        set_realm_remark "$lport" "$remarks"
    fi
    
    systemctl restart realm
    
    echo -e "${GREEN}规则已添加 ($msg_proto) 并重启服务！${PLAIN}"
}

get_realm_rules() {
    if [ ! -f "$REALM_CONFIG" ]; then return; fi
    
    r_lport=()
    r_ip=()
    r_port=()
    r_proto=()
    
    curr_lport=""
    curr_ip=""
    curr_port=""
    curr_proto="tcp+udp"
    in_block=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')
        
        if [[ "$line" == "[[endpoints]]" ]]; then
            if [[ $in_block -eq 1 ]]; then
                r_lport+=("$curr_lport")
                r_ip+=("$curr_ip")
                r_port+=("$curr_port")
                r_proto+=("$curr_proto")
            fi
            in_block=1
            curr_lport=""
            curr_ip=""
            curr_port=""
            curr_proto="tcp+udp"
            
        elif [[ $in_block -eq 1 ]]; then
            if [[ "$line" == listen* ]]; then
                val=$(echo "$line" | awk -F'=' '{print $2}' | tr -d ' "')
                curr_lport=${val##*:} 
            elif [[ "$line" == remote* ]]; then
                val=$(echo "$line" | awk -F'=' '{print $2}' | tr -d ' "')
                curr_port=${val##*:}
                curr_ip=${val%:*}
            elif [[ "$line" == network* ]]; then
                if [[ "$line" == *"tcp"* && "$line" != *"udp"* ]]; then
                    curr_proto="tcp"
                elif [[ "$line" == *"udp"* && "$line" != *"tcp"* ]]; then
                    curr_proto="udp"
                fi
            fi
        fi
    done < "$REALM_CONFIG"

    if [[ $in_block -eq 1 ]]; then
        r_lport+=("$curr_lport")
        r_ip+=("$curr_ip")
        r_port+=("$curr_port")
        r_proto+=("$curr_proto")
    fi
}

show_realm_list() {
    get_realm_rules
    init_remark_file
    if [ ${#r_lport[@]} -eq 0 ]; then
        echo -e "${YELLOW}目前没有任何规则。${PLAIN}"
        return 1
    fi
    
    echo -e "${YELLOW}当前 realm 规则列表：${PLAIN}"
    echo ""
    for ((i=0; i<${#r_lport[@]}; i++)); do
        p_show="${r_proto[$i]}"
        if [[ "$p_show" == "tcp+udp" ]]; then
            p_str="TCP + UDP"
        else
            p_str="${p_show^^}"
        fi
        
        curr_remark=$(get_realm_remark "${r_lport[$i]}")
        
        echo -e "${GREEN}[$((i+1))]${PLAIN} 备注: ${BLUE}${curr_remark}${PLAIN}"
        echo -e "    协议: ${YELLOW}${p_str}${PLAIN}  本地: [::]:${r_lport[$i]}  -->  目标: ${r_ip[$i]}:${r_port[$i]}"
        echo "" 
    done
    return 0
}

view_realm_rules() {
    echo ""
    show_realm_list
    if [ $? -ne 0 ]; then
        echo ""
        read -p "按回车键继续..."
        return
    fi

    echo "0. 返回上一级"
    echo ""
    read -p "请输入选项 [0]: " choice
    if [[ "$choice" != "0" ]]; then
        echo ""
    fi
}

delete_realm_rule() {
    while true; do
        echo -e "\n${YELLOW}删除 realm 规则${PLAIN}"
        echo ""
        
        show_realm_list
        if [ $? -ne 0 ]; then
            echo ""
            read -p "按回车键继续..."
            return
        fi

        echo "0. 返回上一级"
        echo ""
        
        read -p "请输入选项 [0-${#r_lport[@]}]: " num
        
        if [[ "$num" == "0" ]]; then return; fi
        
        echo "" 

        if [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#r_lport[@]}" ]; then
            echo -e "${RED}请输入正确的序号！${PLAIN}\n"
            read -p "按回车键重试..."
            continue
        fi
        
        idx=$((num-1))
        
        del_realm_remark "${r_lport[$idx]}"
        
        unset r_lport[$idx]
        unset r_ip[$idx]
        unset r_port[$idx]
        unset r_proto[$idx]
        
        rebuild_realm_config
        systemctl restart realm
        
        echo -e "${GREEN}规则已删除！${PLAIN}\n"
        read -p "按回车键继续..."
    done
}

edit_realm_rule() {
    while true; do
        echo -e "\n${YELLOW}修改 realm 规则${PLAIN}"
        echo ""
        
        show_realm_list
        if [ $? -ne 0 ]; then
            echo ""
            read -p "按回车键继续..."
            return
        fi
        
        echo "0. 返回主菜单"
        echo ""
        
        read -p "请输入选项 [0-${#r_lport[@]}]: " num
        
        if [[ "$num" == "0" ]]; then return; fi
        
        echo ""

        if [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "${#r_lport[@]}" ]; then
            echo -e "${RED}请输入正确的序号！${PLAIN}\n"
            read -p "按回车键重试..."
            continue
        fi
        
        idx=$((num-1))
        old_remark=$(get_realm_remark "${r_lport[$idx]}")
        
        echo -e "正在修改第 ${GREEN}$num${PLAIN} 条规则 (直接回车保持原值):"
        echo ""
        
        read -p "本地监听端口 (当前: ${r_lport[$idx]}): " new_lport
        echo ""
        read -p "目标 IP/域名 (当前: ${r_ip[$idx]}): " new_ip
        echo ""
        read -p "目标端口 (当前: ${r_port[$idx]}): " new_port
        echo ""
        
        read -p "备注名称 (当前: $old_remark): " new_remark
        echo ""
        
        curr_proto_raw="${r_proto[$idx]}"
        if [[ "$curr_proto_raw" == "tcp+udp" ]]; then
            curr_proto_disp="TCP + UDP"
        else
            curr_proto_disp="${curr_proto_raw^^}"
        fi
        
        echo "协议 (当前: $curr_proto_disp)"
        echo ""
        echo "1. TCP + UDP"
        echo ""
        echo "2. 仅 TCP"
        echo ""
        echo "3. 仅 UDP"
        echo ""
        
        read -p "请输入选项 [1-3 回车默认1]: " new_proto_choice
        echo ""
        
        [[ -z "$new_lport" ]] && new_lport=${r_lport[$idx]}
        [[ -z "$new_ip" ]] && new_ip=${r_ip[$idx]}
        [[ -z "$new_port" ]] && new_port=${r_port[$idx]}
        
        if [[ -z "$new_proto_choice" ]]; then
            new_proto_choice="1"
        fi
        
        case "$new_proto_choice" in
            1) new_proto="tcp+udp" ;;
            2) new_proto="tcp" ;;
            3) new_proto="udp" ;;
            *) new_proto="tcp+udp" ;; 
        esac
        
        if [[ "${r_lport[$idx]}" != "$new_lport" ]]; then
            del_realm_remark "${r_lport[$idx]}"
            if [[ -z "$new_remark" && "$old_remark" != "无" ]]; then
                set_realm_remark "$new_lport" "$old_remark"
            elif [[ -n "$new_remark" ]]; then
                set_realm_remark "$new_lport" "$new_remark"
            fi
        else
             if [[ -n "$new_remark" ]]; then
                set_realm_remark "$new_lport" "$new_remark"
             fi
        fi

        r_lport[$idx]=$new_lport
        r_ip[$idx]=$new_ip
        r_port[$idx]=$new_port
        r_proto[$idx]=$new_proto
        
        rebuild_realm_config
        systemctl restart realm
        
        echo -e "${GREEN}规则已修改并生效！${PLAIN}\n"
        read -p "按回车键继续..."
    done
}

rebuild_realm_config() {
    > $REALM_CONFIG
    
    cat >> $REALM_CONFIG <<EOF
[dns]
mode = "ipv4_and_ipv6"
protocol = "tcp_and_udp"
nameservers = ["1.1.1.1:53", "1.0.0.1:53"]
min_ttl = 600
max_ttl = 3600
cache_size = 256

[network]
use_udp = true
zero_copy = true
fast_open = false
tcp_timeout = 300
udp_timeout = 30
send_proxy = false
send_proxy_version = 2
accept_proxy = false
accept_proxy_timeout = 5

EOF

    for i in "${!r_lport[@]}"; do
        echo "[[endpoints]]" >> $REALM_CONFIG
        echo "listen = \"[::]:${r_lport[$i]}\"" >> $REALM_CONFIG
        echo "remote = \"${r_ip[$i]}:${r_port[$i]}\"" >> $REALM_CONFIG
        
        if [[ "${r_proto[$i]}" == "tcp" ]]; then
            echo "network = \"tcp\"" >> $REALM_CONFIG
        elif [[ "${r_proto[$i]}" == "udp" ]]; then
            echo "network = \"udp\"" >> $REALM_CONFIG
        else
            echo "# network = \"tcp+udp\"" >> $REALM_CONFIG
        fi
        echo "" >> $REALM_CONFIG
    done
}

send_tg_msg() {
    if [[ -f "$TG_CONF" ]]; then
        source "$TG_CONF"
        if [[ -n "$TG_BOT_TOKEN" && -n "$TG_CHAT_ID" ]]; then
            curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" -d chat_id="${TG_CHAT_ID}" -d text="$1" >/dev/null 2>&1
        fi
    fi
}

ensure_block_chain() {
    if ! nft list table inet realm_block >/dev/null 2>&1; then
        nft add table inet realm_block
        nft add chain inet realm_block input { type filter hook input priority -300 \; }
    fi
}

init_nftables() {
    # 1. 建立基础表和链（如果不存在）
    if ! nft list table inet realm_stats >/dev/null 2>&1; then
        nft add table inet realm_stats
        nft add chain inet realm_stats input_counter { type filter hook input priority 0 \; }
        nft add chain inet realm_stats output_counter { type filter hook output priority 0 \; }
    fi

    # 2. 自动扫描当前配置文件中的所有端口并添加监控规则
    get_realm_rules
    if [ ${#r_lport[@]} -gt 0 ]; then
        for port in "${r_lport[@]}"; do
            if [[ "$port" =~ ^[0-9]+$ ]]; then
                if ! nft list chain inet realm_stats input_counter | grep "tcp dport $port" >/dev/null 2>&1; then
                    nft add rule inet realm_stats input_counter tcp dport $port counter
                fi
                if ! nft list chain inet realm_stats output_counter | grep "tcp sport $port" >/dev/null 2>&1; then
                    nft add rule inet realm_stats output_counter tcp sport $port counter
                fi
                if ! nft list chain inet realm_stats input_counter | grep "udp dport $port" >/dev/null 2>&1; then
                    nft add rule inet realm_stats input_counter udp dport $port counter
                fi
                if ! nft list chain inet realm_stats output_counter | grep "udp sport $port" >/dev/null 2>&1; then
                    nft add rule inet realm_stats output_counter udp sport $port counter
                fi
            fi
        done
    fi
}

get_port_traffic() {
    local port=$1
    if ! nft list chain inet realm_stats input_counter | grep "tcp dport $port" >/dev/null 2>&1; then
        nft add rule inet realm_stats input_counter tcp dport $port counter
    fi
    if ! nft list chain inet realm_stats output_counter | grep "tcp sport $port" >/dev/null 2>&1; then
        nft add rule inet realm_stats output_counter tcp sport $port counter
    fi
    if ! nft list chain inet realm_stats input_counter | grep "udp dport $port" >/dev/null 2>&1; then
        nft add rule inet realm_stats input_counter udp dport $port counter
    fi
    if ! nft list chain inet realm_stats output_counter | grep "udp sport $port" >/dev/null 2>&1; then
        nft add rule inet realm_stats output_counter udp sport $port counter
    fi
    rx_tcp=$(nft list chain inet realm_stats input_counter | grep "tcp dport $port" | awk '{for(i=1;i<=NF;i++) if($i=="bytes") print $(i+1)}')
    tx_tcp=$(nft list chain inet realm_stats output_counter | grep "tcp sport $port" | awk '{for(i=1;i<=NF;i++) if($i=="bytes") print $(i+1)}')
    rx_udp=$(nft list chain inet realm_stats input_counter | grep "udp dport $port" | awk '{for(i=1;i<=NF;i++) if($i=="bytes") print $(i+1)}')
    tx_udp=$(nft list chain inet realm_stats output_counter | grep "udp sport $port" | awk '{for(i=1;i<=NF;i++) if($i=="bytes") print $(i+1)}')
    rx=$(( ${rx_tcp:-0} + ${rx_udp:-0} ))
    tx=$(( ${tx_tcp:-0} + ${tx_udp:-0} ))
    echo "${rx:-0} ${tx:-0}"
}

format_bytes() {
    local b=$1
    if [[ $b -lt 1024 ]]; then
        echo "${b} B"
    elif [[ $b -lt 1048576 ]]; then
        echo "$((b/1024)) KB"
    elif [[ $b -lt 1073741824 ]]; then
        echo "$((b/1048576)) MB"
    else
        echo "$((b/1073741824)) GB"
    fi
}

get_visual_length() {
    local s=$1
    local c=$(echo -e "$s" | sed "s/\x1B\[[0-9;]*[a-zA-Z]//g")
    echo $(( ${#c} + ( $(echo -n "$c" | wc -c) - ${#c} ) / 2 ))
}

get_padding() {
    local length=$1
    if [[ -z "$length" || ! "$length" =~ ^[0-9]+$ ]]; then length=1; fi
    if [[ "$length" -lt 1 ]]; then length=1; fi
    printf "%${length}s" ""
}

center_line() {
    local s=$1
    local cols
    cols=$(tput cols 2>/dev/null)
    if [[ -z "$cols" || ! "$cols" =~ ^[0-9]+$ ]]; then
        cols=100
    fi
    local len=$(get_visual_length "$s")
    local pad=$(( (cols - len) / 2 ))
    if [[ "$pad" -lt 0 ]]; then pad=0; fi
    printf "%*s%b\n" "$pad" "" "$s"
}

center_line_width() {
    local s=$1
    local width_str=$2
    local width=$(get_visual_length "$width_str")
    local len=$(get_visual_length "$s")
    local pad=$(( (width - len) / 2 ))
    if [[ "$pad" -lt 0 ]]; then pad=0; fi
    printf "%*s%b\n" "$pad" "" "$s"
}

get_port_name() {
    local port=$1
    local remark=$(get_realm_remark "$port")
    if [[ -z "$remark" || "$remark" == "无" ]]; then
        echo "端口-$port"
    else
        echo "$remark-$port"
    fi
}

is_manual_blocked() {
    local port=$1
    [[ -f "$TRAFFIC_DIR/manual_block_${port}.conf" ]]
}

ensure_monitor_timer() {
    cat > "$MONITOR_SERVICE" <<EOF
[Unit]
Description=Forwarding Traffic Monitor

[Service]
Type=oneshot
ExecStart=/bin/bash $SCRIPT_PATH monitor
EOF

    cat > "$MONITOR_TIMER" <<EOF
[Unit]
Description=Forwarding Traffic Monitor Timer

[Timer]
OnBootSec=10s
OnUnitActiveSec=10s
AccuracySec=1s
Unit=forwarding-traffic.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now forwarding-traffic.timer >/dev/null 2>&1
}

set_reset_timer() {
    local port=$1
    local name=$2
    local day=$3
    local svc="/etc/systemd/system/realm-reset-${port}.service"
    local timer="/etc/systemd/system/realm-reset-${port}.timer"

    systemctl disable --now "realm-reset-${port}.timer" >/dev/null 2>&1
    rm -f "$svc" "$timer"

    if [[ "$day" == "0" ]]; then
        systemctl daemon-reload
        return
    fi

    cat > "$svc" <<EOF
[Unit]
Description=Realm Reset Port ${port}

[Service]
Type=oneshot
ExecStart=/bin/bash $SCRIPT_PATH reset_port_exec $port "$name"
EOF

    cat > "$timer" <<EOF
[Unit]
Description=Realm Reset Port ${port} (monthly)

[Timer]
OnCalendar=*-*-$(printf "%02d" "$day") 00:00:00
Persistent=true
Unit=realm-reset-${port}.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "realm-reset-${port}.timer" >/dev/null 2>&1
}

show_traffic() {
    mkdir -p "$TRAFFIC_DIR"
    init_nftables
    local header_str="------------ 端口流量监控与限制 (Traffic Monitor) ------------"
    local sep_line="-------------------------------------------------------------------------------------------------------------"
    center_line_width "${YELLOW}${header_str}${PLAIN}" "$sep_line"
    echo -e "$sep_line"
    get_realm_rules
    if [ ${#r_lport[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无规则${PLAIN}"
    else
        for ((i=0; i<${#r_lport[@]}; i++)); do
            port="${r_lport[$i]}"
            name=$(get_port_name "$port")
            read rx tx <<< $(get_port_traffic "$port")
            total=$((rx + tx))
            rx_f=$(format_bytes $rx)
            tx_f=$(format_bytes $tx)
            total_f=$(format_bytes $total)
            status_text=""
            is_stopped=false
            if [[ -f "$TRAFFIC_DIR/limit_${port}.conf" ]]; then
                limit=$(cat "$TRAFFIC_DIR/limit_${port}.conf")
                l_bytes=$((limit * 1024 * 1024 * 1024))
                if [[ $total -ge $l_bytes ]]; then
                    status_text="${RED}已停用${PLAIN}"
                    is_stopped=true
                else
                    status_text="${YELLOW}限${limit}G${PLAIN}"
                fi
            fi
            if [[ -f "$TRAFFIC_DIR/limit_rate_${port}.conf" && "$is_stopped" == "false" ]]; then
                rate=$(cat "$TRAFFIC_DIR/limit_rate_${port}.conf")
                if [[ -n "$status_text" ]]; then
                    status_text="${status_text} ${YELLOW}限速${rate}M${PLAIN}"
                else
                    status_text="${YELLOW}限速${rate}M${PLAIN}"
                fi
            fi
            if [[ -z "$status_text" ]]; then status_text="${PLAIN}正常${PLAIN}"; fi
            v_len=$(get_visual_length "$name")
            pad_len=$((30 - v_len - 7))
            padding=$(get_padding "$pad_len")
            
            printf "${GREEN}%d.${PLAIN}    %s%s ${PLAIN}出↑${PLAIN} %-12s    ${PLAIN}入↓${PLAIN} %-12s    ${PLAIN}总:${PLAIN} %-12s    %b\n" \
            "$((i+1))" "$name" "$padding" "$tx_f" "$rx_f" "$total_f" "$status_text"
            
            if [[ $i -lt $(( ${#r_lport[@]} - 1 )) ]]; then echo -e ""; fi
        done
    fi
    echo -e "$sep_line"
    echo -e ""
    echo -e " ${GREEN}1.${PLAIN} 刷新统计"
    echo -e ""
    echo -e " ${GREEN}2.${PLAIN} 设置流量限制"
    echo -e ""
    echo -e " ${GREEN}3.${PLAIN} 设置端口限速"
    echo -e ""
    echo -e " ${GREEN}4.${PLAIN} 端口管理"
    echo -e ""
    echo -e " ${GREEN}5.${PLAIN} 重置流量统计数据"
    echo -e ""
    echo -e " ${GREEN}6.${PLAIN} 设置 Telegram 通知"
    echo -e ""
    echo -e " ${GREEN}0.${PLAIN} 返回上一页"
    echo -e ""
    read -p "选项[0-6]: " c
    if [[ "$c" != "0" ]]; then
        echo -e ""
    fi
    case "$c" in
        1) show_traffic ;;
        2) set_traffic_quota ;;
        3) set_port_limit ;;
        4) port_manager_menu ;;
        5) reset_traffic_menu ;;
        6) setup_tg_notify ;;
        0) return ;;
        *) show_traffic ;;
    esac
}

port_manager_menu() {
    echo -e "${YELLOW}------------ 端口管理 ------------${PLAIN}"
    echo -e ""
    get_realm_rules
    if [ ${#r_lport[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无规则${PLAIN}"
        echo -e ""
        read -n 1 -s -r -p "按任意键返回..."
        echo -e ""
        echo -e ""
        show_traffic
        return
    fi
    for ((i=0; i<${#r_lport[@]}; i++)); do
        name=$(get_port_name "${r_lport[$i]}")
        echo -e " ${GREEN}$((i+1)).${PLAIN} ${name}"
        echo -e ""
    done
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "选择[0-${#r_lport[@]}]: " idx
    echo -e ""
    if [[ "$idx" == "0" ]]; then show_traffic; return; fi
    if [[ ! "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 ]] || [[ "$idx" -gt "${#r_lport[@]}" ]]; then
        port_manager_menu
        return
    fi
    real=$((idx-1))
    port_action_menu "${r_lport[$real]}"
}

port_action_menu() {
    local port=$1
    local status="${GREEN}running${PLAIN}"
    ensure_block_chain
    if nft list chain inet realm_block input | grep -q "dport $port drop"; then
        status="${RED}stopped${PLAIN}"
    fi
    echo -e "${YELLOW}------------ 端口管理 ------------${PLAIN}"
    echo -e ""
    echo -e " 端口: ${port}  状态: ${status}"
    echo -e ""
    echo -e " ${GREEN}1.${PLAIN} 打开端口"
    echo -e ""
    echo -e " ${GREEN}2.${PLAIN} 关闭端口"
    echo -e ""
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "请选择[0-2]: " opt
    echo -e ""
    case "$opt" in
        1)
            rm -f "$TRAFFIC_DIR/manual_block_${port}.conf"
            while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
            while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
            echo -e "${GREEN}端口已开启！${PLAIN}"
            echo -e ""
            read -n 1 -s -r -p "按任意键返回..."
            echo -e ""
            echo -e ""
            port_action_menu "$port"
            ;;
        2)
            echo "1" > "$TRAFFIC_DIR/manual_block_${port}.conf"
            if ! nft list chain inet realm_block input | grep -q "tcp dport $port drop"; then
                nft add rule inet realm_block input tcp dport $port drop
            fi
            if ! nft list chain inet realm_block input | grep -q "udp dport $port drop"; then
                nft add rule inet realm_block input udp dport $port drop
            fi
            echo -e "${GREEN}端口已关闭！${PLAIN}"
            echo -e ""
            read -n 1 -s -r -p "按任意键返回..."
            echo -e ""
            echo -e ""
            port_action_menu "$port"
            ;;
        0) port_manager_menu ;;
        *) port_action_menu "$port" ;;
    esac
}

setup_tg_notify() {
    mkdir -p "$TRAFFIC_DIR"
    echo -e "${YELLOW}------------ 设置 Telegram 通知 ------------${PLAIN}"
    echo -e ""
    if [[ -f "$TG_CONF" ]]; then
        source "$TG_CONF"
        echo -e "当前 Token: ${GREEN}${TG_BOT_TOKEN:0:10}******${PLAIN}"
        echo -e "当前 ChatID: ${GREEN}${TG_CHAT_ID}${PLAIN}"
    else
        echo -e "当前状态: ${YELLOW}未配置${PLAIN}"
    fi
    echo -e ""
    echo -e " ${GREEN}1.${PLAIN} 配置/修改"
    echo -e ""
    echo -e " ${GREEN}2.${PLAIN} 测试消息"
    echo -e ""
    echo -e " ${GREEN}3.${PLAIN} 清除配置"
    echo -e ""
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "选项[0-3]: " o
    echo -e ""
    case "$o" in
        1) 
           read -p "Token: " t
           read -p "ChatID: " c
           echo "TG_BOT_TOKEN=\"$t\"" > "$TG_CONF"
           echo "TG_CHAT_ID=\"$c\"" >> "$TG_CONF"
           echo -e "${GREEN}保存成功${PLAIN}"
           echo -e ""
           read -n 1 -s -r -p "按键返回..."
           echo -e ""
           setup_tg_notify 
           ;;
        2) 
           echo -e "${YELLOW}发送中...${PLAIN}"
           send_tg_msg "转发脚本 通知测试"
           echo -e "${GREEN}发送完成${PLAIN}"
           echo -e ""
           read -n 1 -s -r -p "按键返回..."
           echo -e ""
           setup_tg_notify 
           ;;
        3) 
           rm -f "$TG_CONF"
           echo -e "${GREEN}已清除${PLAIN}"
           echo -e ""
           read -n 1 -s -r -p "按键返回..."
           echo -e ""
           setup_tg_notify 
           ;;
        0) show_traffic ;;
        *) setup_tg_notify ;;
    esac
}

set_traffic_quota() {
    mkdir -p "$TRAFFIC_DIR"
    echo -e "${YELLOW}------------ 设置流量限制 ------------${PLAIN}"
    get_realm_rules
    echo -e ""
    for ((i=0; i<${#r_lport[@]}; i++)); do
        name=$(get_port_name "${r_lport[$i]}")
        echo -e " ${GREEN}$((i+1)).${PLAIN} ${name}"
        echo -e ""
    done
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "选择[0-${#r_lport[@]}]: " idx
    echo -e ""
    if [[ "$idx" == "0" ]]; then show_traffic; return; fi
    real=$((idx-1))
    port="${r_lport[$real]}"
    read -p "流量配额(GB, 0取消): " gb
    echo -e ""
    if [[ "$gb" == "0" ]]; then
        rm -f "$TRAFFIC_DIR/limit_${port}.conf"
        ensure_block_chain
        while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
            nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
        done
        while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
            nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
        done
        echo -e "${YELLOW}已取消限制${PLAIN}"
    else
        echo "$gb" > "$TRAFFIC_DIR/limit_${port}.conf"
        ensure_block_chain
        ensure_monitor_timer
        
        read rx tx <<< $(get_port_traffic "$port")
        total=$((rx + tx))
        limit_bytes=$((gb * 1024 * 1024 * 1024))
        if [[ $total -ge $limit_bytes ]]; then
            if ! nft list chain inet realm_block input | grep -q "tcp dport $port drop"; then
                nft add rule inet realm_block input tcp dport $port drop
            fi
            if ! nft list chain inet realm_block input | grep -q "udp dport $port drop"; then
                nft add rule inet realm_block input udp dport $port drop
            fi
        else
            while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
            while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
        fi
        
        echo -e "${GREEN}设置完成 (已启动后台自动监控)${PLAIN}"
    fi
    echo -e ""
    read -n 1 -s -r -p "按键返回..."
    echo -e ""
    echo -e ""
    show_traffic
}

set_port_limit() {
    mkdir -p "$TRAFFIC_DIR"
    echo -e "${YELLOW}------------ 设置端口限速 ------------${PLAIN}"
    get_realm_rules
    echo -e ""
    for ((i=0; i<${#r_lport[@]}; i++)); do
        name=$(get_port_name "${r_lport[$i]}")
        echo -e " ${GREEN}$((i+1)).${PLAIN} ${name}"
        echo -e ""
    done
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "选择[0-${#r_lport[@]}]: " idx
    echo -e ""
    if [[ "$idx" == "0" ]]; then show_traffic; return; fi
    real=$((idx-1))
    port="${r_lport[$real]}"
    dev=$(ip route|grep default|head -n1|awk '{print $5}')
    read -p "限速(Mbps, 0取消): " limit
    echo -e ""
    tc filter del dev $dev parent 1:0 protocol ip prio 1 u32 match ip sport $port 0xffff >/dev/null 2>&1
    tc class del dev $dev parent 1:1 classid 1:$(printf "%x" $port) >/dev/null 2>&1
    if [[ "$limit" == "0" ]]; then
        rm -f "$TRAFFIC_DIR/limit_rate_${port}.conf"
        echo -e "${YELLOW}已取消限速${PLAIN}"
    else
        if ! tc qdisc show dev $dev | grep -q "htb 1:"; then
             tc qdisc add dev $dev root handle 1: htb default 10
             tc class add dev $dev parent 1: classid 1:1 htb rate 1000mbit
        fi
        k=$((limit*1000))
        class_id="1:$(printf "%x" $port)"
        tc class add dev $dev parent 1:1 classid $class_id htb rate ${k}kbit ceil ${k}kbit
        tc filter add dev $dev protocol ip parent 1:0 prio 1 u32 match ip sport $port 0xffff flowid $class_id
        echo "$limit" > "$TRAFFIC_DIR/limit_rate_${port}.conf"
        echo -e "${GREEN}设置完成${PLAIN}"
    fi
    echo -e ""
    read -n 1 -s -r -p "按键返回..."
    echo -e ""
    echo -e ""
    show_traffic
}

reset_traffic_menu() {
    mkdir -p "$TRAFFIC_DIR"
    local header_str="------------ 重置流量统计 ------------"
    local header_len=$(get_visual_length "$header_str")
    echo -e "${YELLOW}${header_str}${PLAIN}"
    get_realm_rules
    echo -e ""
    for ((i=0; i<${#r_lport[@]}; i++)); do
        name=$(get_port_name "${r_lport[$i]}")
        port="${r_lport[$i]}"
        timer="realm-reset-${port}.timer"
        if systemctl list-timers --all | grep -q "$timer"; then
            day=$(systemctl cat "$timer" 2>/dev/null | grep "^OnCalendar=" | awk -F'-' '{print $3}' | awk '{print $1}' | sed 's/^0//')
            if [[ -n "$day" ]]; then
                st_text="每月${day}号重置"
            else
                st_text="已设置自动"
            fi
            st_color="${YELLOW}${st_text}${PLAIN}"
        else
            st_text="未设置自动"
            st_color="${PLAIN}${st_text}${PLAIN}"
        fi
        prefix_plain=" $((i+1)). ${name}"
        prefix_color=" ${GREEN}$((i+1)).${PLAIN} ${name}"
        status_plain="(${st_text})"
        status_color="(${st_color})"
        prefix_len=$(get_visual_length "$prefix_plain")
        status_len=$(get_visual_length "$status_plain")
        pad_len=$((header_len - prefix_len - status_len))
        if [[ $pad_len -lt 1 ]]; then pad_len=1; fi
        padding=$(get_padding "$pad_len")
        printf "%b%s%b\n" "$prefix_color" "$padding" "$status_color"
        echo -e ""
    done
    echo -e " ${GREEN}$(( ${#r_lport[@]} + 1 )).${PLAIN} 重置所有"
    echo -e ""
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "请选择[0-$(( ${#r_lport[@]} + 1 ))]: " idx 
    echo -e ""
    if [[ "$idx" == "0" ]]; then show_traffic; return; fi
    if [[ "$idx" == "$(( ${#r_lport[@]} + 1 ))" ]]; then
        nft flush chain inet realm_stats input_counter
        nft flush chain inet realm_stats output_counter
        ensure_block_chain
        for port in "${r_lport[@]}"; do
            while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
            while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
        done
        echo -e "${GREEN}已重置所有${PLAIN}"
        echo -e "" 
        read -n 1 -s -r -p "按键返回..."
        echo -e ""
        echo -e ""
        reset_traffic_menu
        return
    fi
    real=$((idx-1))
    port="${r_lport[$real]}"
    name=$(get_port_name "$port")
    echo -e " ${GREEN}1.${PLAIN} 立即清零"
    echo -e ""
    echo -e " ${GREEN}2.${PLAIN} 设置自动重置日"
    echo -e ""
    echo -e " ${GREEN}0.${PLAIN} 返回"
    echo -e ""
    read -p "请选择[0-2]: " op 
    echo -e ""
    if [[ "$op" == "0" ]]; then reset_traffic_menu; return; fi
    if [[ "$op" == "1" ]]; then
        ensure_block_chain
        while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
            nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
        done
        while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
            nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
        done
        nft delete rule inet realm_stats input_counter handle $(nft -a list chain inet realm_stats input_counter | grep "tcp dport $port" | awk '{print $NF}') 2>/dev/null
        nft delete rule inet realm_stats output_counter handle $(nft -a list chain inet realm_stats output_counter | grep "tcp sport $port" | awk '{print $NF}') 2>/dev/null
        nft delete rule inet realm_stats input_counter handle $(nft -a list chain inet realm_stats input_counter | grep "udp dport $port" | awk '{print $NF}') 2>/dev/null
        nft delete rule inet realm_stats output_counter handle $(nft -a list chain inet realm_stats output_counter | grep "udp sport $port" | awk '{print $NF}') 2>/dev/null
        nft add rule inet realm_stats input_counter tcp dport $port counter
        nft add rule inet realm_stats output_counter tcp sport $port counter
        nft add rule inet realm_stats input_counter udp dport $port counter
        nft add rule inet realm_stats output_counter udp sport $port counter
        echo -e "${GREEN}已清零${PLAIN}"
        echo -e "" 
        read -n 1 -s -r -p "按键返回..."
        echo -e ""
        echo -e ""
        reset_traffic_menu
    elif [[ "$op" == "2" ]]; then
        read -p "每月几号(1-31, 0关闭): " d
        echo -e ""
        set_reset_timer "$port" "$name" "$d"
        echo -e "${GREEN}设置成功${PLAIN}"
        echo -e "" 
        read -n 1 -s -r -p "按键返回..."
        echo -e ""
        echo -e ""
        reset_traffic_menu
    fi
}

uninstall_realm() {
    echo "" 
    read -p "确定要卸载 realm 吗？(y/n): " choice
    if [[ "$choice" == "y" ]]; then
        echo "" 
        systemctl stop realm
        systemctl disable realm
        rm -f $REALM_SERVICE
        rm -f $REALM_PATH
        rm -rf /etc/realm
        rm -f $REMARK_FILE
        systemctl daemon-reload
        echo ""
        echo -e "${GREEN}realm 已卸载${PLAIN}"
        echo ""
        read -p "按回车键继续..."
    fi
}

reset_realm_rules() {
    echo -e "\n${YELLOW}清空 realm 规则${PLAIN}\n"
    show_realm_list
    if [ $? -ne 0 ]; then
        echo ""
        read -p "按回车键继续..."
        return 
    fi

    read -p "确定要清空所有 realm 规则吗？(y/n): " choice
    
    if [[ "$choice" == "y" ]]; then
        rebuild_realm_config
        > $REMARK_FILE
        systemctl restart realm
        echo -e "\n${GREEN}realm 规则已清空 (保留全局优化配置)！${PLAIN}"
        echo "" 
        read -p "按回车键继续..."
    fi
}

install_iptables_env() {
    echo -e "${YELLOW}安装/更新 iptables...${PLAIN}\n"
    
    if [ -f /etc/debian_version ]; then
        apt-get update && apt-get install -y iptables iptables-persistent
    elif [ -f /etc/redhat-release ]; then
        yum install -y iptables iptables-services
    fi
    echo "" 
    enable_forwarding
    
    if [ -f /etc/debian_version ]; then
        systemctl enable --now netfilter-persistent
    else
        systemctl enable --now iptables
    fi
    
    echo ""
    echo -e "${GREEN}iptables 安装完成！${PLAIN}"
}

add_iptables_rule() {
    echo -e "\n${YELLOW}添加 iptables 转发规则${PLAIN}\n"
    
    read -p "请输入本地端口: " lport
    echo ""
    read -p "请输入目标 IP: " rip
    echo ""
    read -p "请输入目标端口: " rport
    echo ""
    read -p "请输入备注名称: " remarks
    echo ""
    
    echo "请选择转发协议:"
    echo ""
    echo "1. TCP + UDP"
    echo ""
    echo "2. 仅 TCP"
    echo ""
    echo "3. 仅 UDP"
    echo ""
    read -p "请输入选项 [1-3 回车默认1]: " proto_choice
    echo "" 
    
    if [[ -z "$proto_choice" ]]; then
        proto_choice="1"
    fi
    
    case "$proto_choice" in
        1) proto="both" ;;
        2) proto="tcp" ;;
        3) proto="udp" ;;
        *) proto="both" ;;
    esac

    comment_arg=""
    if [ -n "$remarks" ]; then
        comment_arg="-m comment --comment \"$remarks\""
    fi

    if [ "$proto" == "both" ]; then
        iptables -t nat -A PREROUTING -p tcp --dport $lport -j DNAT --to-destination $rip:$rport $comment_arg
        iptables -t nat -A PREROUTING -p udp --dport $lport -j DNAT --to-destination $rip:$rport $comment_arg
        iptables -t nat -A POSTROUTING -p tcp -d $rip --dport $rport -j MASQUERADE
        iptables -t nat -A POSTROUTING -p udp -d $rip --dport $rport -j MASQUERADE
    else
        iptables -t nat -A PREROUTING -p $proto --dport $lport -j DNAT --to-destination $rip:$rport $comment_arg
        iptables -t nat -A POSTROUTING -p $proto -d $rip --dport $rport -j MASQUERADE
    fi

    if [ -f /etc/debian_version ]; then
        netfilter-persistent save
    else
        service iptables save
    fi
    
    echo ""
    echo -e "${GREEN}iptables 规则已添加并保存！${PLAIN}"
}

list_iptables_rules() {
    echo -e "\n${YELLOW}当前 iptables 转发规则：${PLAIN}"
    echo "" 
    iptables -t nat -L PREROUTING --line-numbers
    echo ""
    read -p "按回车键返回..."
}

del_iptables_rule() {
    while true; do
        echo -e "\n${YELLOW}删除 iptables 规则${PLAIN}"
        echo ""
        
        line_count=$(iptables -t nat -L PREROUTING --line-numbers | wc -l)
        rule_count=$((line_count - 2))
        
        if [ "$rule_count" -le 0 ]; then
             echo -e "${YELLOW}目前没有任何规则。${PLAIN}"
             echo ""
             read -p "按回车键继续..."
             return
        fi

        iptables -t nat -L PREROUTING --line-numbers
        echo ""

        echo "0. 返回上一级"
        echo ""
        
        read -p "请输入选项 [0-${rule_count}]: " num
        
        if [[ "$num" == "0" ]]; then
            return 
        fi
        
        echo ""

        if [[ ! "$num" =~ ^[0-9]+$ ]]; then
             echo -e "${RED}序号无效！${PLAIN}\n"
             read -p "按回车键重试..."
             continue
        fi

        iptables -t nat -D PREROUTING $num
        
        if [ -f /etc/debian_version ]; then
            netfilter-persistent save
        else
            service iptables save
        fi
        echo ""

        echo -e "${GREEN}规则序号 $num 已删除并保存！${PLAIN}\n"
        read -p "按回车键继续..."
    done
}

uninstall_iptables_rules() {
    echo -e "\n${YELLOW}清空 iptables 规则${PLAIN}\n"
    
    line_count=$(iptables -t nat -L PREROUTING --line-numbers | wc -l)
    rule_count=$((line_count - 2))
    if [ "$rule_count" -le 0 ]; then
         echo -e "${YELLOW}目前没有任何规则。${PLAIN}"
         echo ""
         read -p "按回车键继续..."
         return
    fi
    
    iptables -t nat -L PREROUTING --line-numbers
    echo ""

    read -p "确定要清空所有 iptables 规则并移除持久化配置吗？(y/n): " choice
    
    if [[ "$choice" == "y" ]]; then
        iptables -t nat -F
        
        echo ""
        if [ -f /etc/debian_version ]; then
            netfilter-persistent save
        else
            service iptables save
        fi
        echo ""

        echo -e "${GREEN}iptables 规则已清空。${PLAIN}"
        echo ""
        read -p "按回车键继续..."
    fi
}

uninstall_iptables_service() {
    echo ""
    read -p "确定要卸载 iptables 转发服务吗？(y/n): " choice
    if [[ "$choice" == "y" ]]; then
        echo ""
        iptables -t nat -F
        
        if [ -f /etc/debian_version ]; then
            netfilter-persistent save >/dev/null 2>&1
            systemctl stop netfilter-persistent
            systemctl disable netfilter-persistent
        else
            service iptables save >/dev/null 2>&1
            systemctl stop iptables
            systemctl disable iptables
        fi
        
        echo ""
        echo -e "${GREEN}iptables 已卸载${PLAIN}"
        echo ""
        read -p "按回车键继续..."
    fi
}

uninstall_all() {
    echo ""
    echo -e "${RED}警告：此操作将执行以下所有动作：${PLAIN}"
    echo ""
    echo "1. 卸载 realm (删除文件、配置、备注和服务)"
    echo ""
    echo "2. 清空 iptables 转发规则"
    echo ""
    echo "3. 清理端口流量监控配置"
    echo ""
    echo "4. 删除本脚本及 'zf' 快捷键"
    echo ""
    read -p "确定要彻底卸载脚本及所有组件吗？(y/n): " choice
    echo ""
    
    if [[ "$choice" == "y" ]]; then
        systemctl stop realm >/dev/null 2>&1
        systemctl disable realm >/dev/null 2>&1
        rm -f $REALM_SERVICE
        rm -f $REALM_PATH
        
        if [ -d "$TRAFFIC_DIR" ]; then
            dev=$(ip route|grep default|head -n1|awk '{print $5}')
            for file in "$TRAFFIC_DIR"/limit_rate_*.conf; do
                if [[ -f "$file" && -n "$dev" ]]; then
                    port=${file#*limit_rate_}
                    port=${port%.conf}
                    tc filter del dev $dev parent 1:0 protocol ip prio 1 u32 match ip sport $port 0xffff >/dev/null 2>&1
                    tc class del dev $dev parent 1:1 classid 1:$(printf "%x" $port) >/dev/null 2>&1
                fi
            done
            rm -f "$TRAFFIC_DIR"/limit_*.conf
            rm -f "$TRAFFIC_DIR"/limit_rate_*.conf
            rm -f "$TG_CONF"
        fi
        
        nft delete table inet realm_stats >/dev/null 2>&1
        nft delete table inet realm_block >/dev/null 2>&1
        
        if command -v crontab &> /dev/null; then
            crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH reset_port_exec" | crontab -
        fi
        
        systemctl disable --now forwarding-traffic.timer >/dev/null 2>&1
        rm -f "$MONITOR_SERVICE"
        rm -f "$MONITOR_TIMER"
        systemctl daemon-reload
        
        rm -rf /etc/realm
        
        iptables -t nat -F
        
        if [ -f /etc/debian_version ]; then
            netfilter-persistent save
        else
            service iptables save
        fi
        
        rm -f /usr/bin/zf
        echo ""
        echo -e "${GREEN}卸载完成！脚本将自动退出。${PLAIN}"
        echo ""
        rm -f "$SCRIPT_PATH"
        exit 0
    fi
}

manage_realm_menu() {
    while true; do
        echo -e "\n${GREEN}===================================================${PLAIN}"
        echo ""
        echo -e "${YELLOW} ---- 管理 realm 规则 ----${PLAIN}"
        echo ""
        echo " 1. 查看 realm 规则"
        echo ""
        echo " 2. 删除 realm 规则"
        echo ""
        echo " 3. 清空所有 realm 规则"
        echo ""
        echo " 4. 卸载 realm"
        echo ""
        echo " 0. 返回主菜单"
        echo ""
        
        read -p "请输入选项 [0-4]: " sub_num

        case "$sub_num" in
            1) view_realm_rules ;;
            2) delete_realm_rule ;;
            3) reset_realm_rules ;;
            4) uninstall_realm ;;
            0) return ;;
            *) echo -e "\n${RED}请输入正确的数字！${PLAIN}\n"; read -p "按回车键继续..." ;;
        esac
    done
}

manage_iptables_menu() {
    while true; do
        echo -e "\n${GREEN}===================================================${PLAIN}"
        echo ""
        echo -e "${YELLOW} ---- 管理 iptables 规则 ----${PLAIN}"
        echo ""
        echo " 1. 查看 iptables 规则"
        echo ""
        echo " 2. 删除 iptables 规则"
        echo ""
        echo " 3. 清空所有 iptables 规则"
        echo ""
        echo " 4. 卸载 iptables"
        echo ""
        echo " 0. 返回主菜单"
        echo ""
        
        read -p "请输入选项 [0-4]: " sub_num

        case "$sub_num" in
            1) list_iptables_rules ;;
            2) del_iptables_rule ;;
            3) uninstall_iptables_rules ;;
            4) uninstall_iptables_service ;;
            0) return ;;
            *) echo -e "\n${RED}请输入正确的数字！${PLAIN}\n"; read -p "按回车键继续..." ;;
        esac
    done
}

manage_script_menu() {
    while true; do
        echo -e "\n${GREEN}===================================================${PLAIN}"
        echo ""
        echo -e "${YELLOW} ---- 脚本管理 ----${PLAIN}"
        echo ""
        echo " 1. 更新脚本"
        echo ""
        echo " 2. 卸载脚本"
        echo ""
        echo " 0. 返回"
        echo ""
        
        read -p "请输入选项 [0-2]: " sub_num

        case "$sub_num" in
            1) update_script ;;
            2) uninstall_all ;;
            0) return ;;
            *) echo -e "\n${RED}请输入正确的数字！${PLAIN}\n"; read -p "按回车键继续..." ;;
        esac
    done
}

show_menu() {
    check_status
    echo ""
    echo -e "${GREEN}========= 转发脚本 Script v1.7.1 By Shinyuz =========${PLAIN}"
    echo ""
    echo -e " realm: ${realm_status}"
    echo ""
    echo -e " iptables: ${iptables_status}"
    echo ""
    echo -e "${GREEN}===================================================${PLAIN}"
    echo ""
    
    echo -e "${YELLOW} ---- realm 管理 ------${PLAIN}"
    echo ""
    echo " 1. 添加 realm 转发规则"
    echo ""
    echo " 2. 修改 realm 规则"
    echo ""
    echo " 3. 管理 realm 规则"
    echo ""
    echo " 4. 安装/更新 realm"
    echo ""
    
    echo -e "${YELLOW} ---- iptables 管理 ----${PLAIN}"
    echo ""
    echo " 5. 添加 iptables 转发规则"
    echo ""
    echo " 6. 管理 iptables 规则"
    echo ""
    echo " 7. 安装/更新 iptables"
    echo ""
    
    echo "------------------------------"
    echo ""
    echo " 8. 端口流量使用情况"
    echo ""
    echo " 9. 脚本管理"
    echo ""
    echo " 0. 退出脚本"
    echo ""
    
    read -p "请输入选项 [0-9]: " num

    case "$num" in
        1) add_realm_rule; echo ""; read -p "按回车键继续..." ;;
        2) edit_realm_rule ;;
        3) manage_realm_menu ;;
        4) install_realm ;;
        5) add_iptables_rule; echo ""; read -p "按回车键继续..." ;;
        6) manage_iptables_menu ;;
        7) install_iptables_env ;; 
        8) echo ""; show_traffic ;;
        9) manage_script_menu ;;
        0) echo ""; exit 0 ;; 
        *) echo -e "\n${RED}请输入正确的数字！${PLAIN}\n"; read -p "按回车键继续..." ;;
    esac
}

if [[ "$1" == "reset_port_exec" ]]; then
    ensure_block_chain
    nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $2 drop" | awk '{print $NF}') 2>/dev/null
    nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $2 drop" | awk '{print $NF}') 2>/dev/null
    nft delete rule inet realm_stats input_counter handle $(nft -a list chain inet realm_stats input_counter | grep "tcp dport $2" | awk '{print $NF}') 2>/dev/null
    nft delete rule inet realm_stats output_counter handle $(nft -a list chain inet realm_stats output_counter | grep "tcp sport $2" | awk '{print $NF}') 2>/dev/null
    nft delete rule inet realm_stats input_counter handle $(nft -a list chain inet realm_stats input_counter | grep "udp dport $2" | awk '{print $NF}') 2>/dev/null
    nft delete rule inet realm_stats output_counter handle $(nft -a list chain inet realm_stats output_counter | grep "udp sport $2" | awk '{print $NF}') 2>/dev/null
    nft add rule inet realm_stats input_counter tcp dport $2 counter
    nft add rule inet realm_stats output_counter tcp sport $2 counter
    nft add rule inet realm_stats input_counter udp dport $2 counter
    nft add rule inet realm_stats output_counter udp sport $2 counter
    name="$3"
    if [[ -z "$name" ]]; then
        name=$(get_port_name "$2")
    fi
    send_tg_msg "🔔 [流量重置] 端口 ${name} ($2) 已自动重置"
    exit 0
fi

if [[ "$1" == "monitor" ]]; then
    init_nftables
    ensure_block_chain
    for file in "$TRAFFIC_DIR"/limit_*.conf; do
        if [[ -f "$file" ]]; then
            port=${file#*limit_}
            port=${port%.conf}
            limit_gb=$(cat "$file")
            read rx tx <<< $(get_port_traffic "$port")
            total=$((rx + tx))
            limit_bytes=$((limit_gb * 1024 * 1024 * 1024))
        if [[ $total -ge $limit_bytes ]]; then
            is_blocked=$(nft list chain inet realm_block input | grep -E "tcp dport $port drop|udp dport $port drop")
            if [[ -z "$is_blocked" ]]; then
                nft add rule inet realm_block input tcp dport $port drop
                nft add rule inet realm_block input udp dport $port drop
                name=$(get_port_name "$port")
                used_h=$(format_bytes $total)
                msg="🚨 [流量耗尽] 端口 ${name} (${port}) 已自动停止 (已用 ${used_h} / 限额 ${limit_gb}GB)"
                send_tg_msg "$msg"
            fi
        else
            if is_manual_blocked "$port"; then
                continue
            fi
            while nft -a list chain inet realm_block input | grep -q "tcp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "tcp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
            while nft -a list chain inet realm_block input | grep -q "udp dport $port drop"; do
                nft delete rule inet realm_block input handle $(nft -a list chain inet realm_block input | grep "udp dport $port drop" | head -n 1 | awk '{print $NF}') 2>/dev/null
            done
        fi
        fi
    done
    exit 0
fi

check_root
set_shortcut

if [ ! -f "$REALM_PATH" ]; then
    install_realm
    install_iptables_env
fi

while true; do
    show_menu
done
