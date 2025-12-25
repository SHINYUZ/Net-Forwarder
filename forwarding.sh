#!/bin/bash

# ====================================================
#  转发脚本 Script v1.9 By Shinyuz
#  快捷键: zf
#  更新内容: 优化卸载内容的警告排版
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
        echo -e "\n${GREEN}快捷键 'zf' 已设置成功！以后输入 zf 即可打开面板。${PLAIN}\n"
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

    if lsmod | grep -q "ip_tables" || iptables -L >/dev/null 2>&1; then
        iptables_status="${GREEN}running${PLAIN}"
    else
        iptables_status="${RED}stopped${PLAIN}"
    fi
}

update_script() {
    echo -e "\n${YELLOW}正在检查更新...${PLAIN}"
    echo -e "${GREEN}当前版本 v1.9 (优化卸载提示排版)${PLAIN}"
    echo ""
    read -p "按回车键继续..."
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

install_realm() {
    check_arch
    echo -e "\n${YELLOW}正在安装 realm...${PLAIN}\n"
    
    VERSION="v2.7.0"
    URL="https://github.com/zhboner/realm/releases/download/$VERSION/realm-$REALM_ARCH.tar.gz"
    
    wget -O realm.tar.gz $URL
    
    if [ $? -ne 0 ]; then
        echo -e "\n${RED}下载失败 (404 或 网络错误)！已停止安装。${PLAIN}"
        echo -e "${RED}请检查网络连接或 GitHub 是否可访问。${PLAIN}\n"
        rm -f realm.tar.gz
        return
    fi
    
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
    systemctl enable --now realm
    
    echo ""
    echo -e "${GREEN}realm 安装完成！${PLAIN}"
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
    echo -e "\n${YELLOW}安装/更新 iptables...${PLAIN}\n"
    
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
    echo "1. 卸载 Realm (删除文件、配置、备注和服务)"
    echo ""
    echo "2. 清空 Iptables 转发规则"
    echo ""
    echo "3. 删除本脚本及 'zf' 快捷键"
    echo ""
    read -p "确定要彻底卸载脚本及所有组件吗？(y/n): " choice
    echo ""
    
    if [[ "$choice" == "y" ]]; then
        systemctl stop realm >/dev/null 2>&1
        systemctl disable realm >/dev/null 2>&1
        rm -f $REALM_SERVICE
        rm -f $REALM_PATH
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

show_menu() {
    check_status
    echo ""
    echo -e "${GREEN}========= 转发脚本 Script v1.9 By Shinyuz =========${PLAIN}"
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
    echo " 8. 更新"
    echo ""
    echo " 9. 卸载"
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
        8) update_script ;;
        9) uninstall_all ;;
        0) echo ""; exit 0 ;; 
        *) echo -e "\n${RED}请输入正确的数字！${PLAIN}\n"; read -p "按回车键继续..." ;;
    esac
}

check_root
set_shortcut
while true; do
    show_menu
done
