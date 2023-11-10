#!/bin/bash
export LANG="en_US.UTF-8"
BK='\033[0;30m'
RE='\033[0;31m'
GR='\033[0;32m'
YE='\033[0;33m'
BL='\033[0;34m'
MA='\033[0;35m'
CY='\033[0;36m'
WH='\033[0;37m'
NC='\033[0m'
# echo -e "BL=BLACK RE=RED GR=GREEN YE=YELLOW BL=BLUE MA=MAGENTA CY=CYAN WH=WHITE NC=RESET"
clear_screen() {
    if command -v apt &>/dev/null; then
        clear
    elif command -v yum &>/dev/null; then
        printf "\033c"
    else
        echo
        echo -e "${BK}■ ${RE}■ ${GR}■ ${YE}■ ${BL}■ ${MA}■ ${CY}■ ${WH}■ ${BL}■ ${GR}■ ${BK}■"
    fi
}
echoo() {
    if [ ${#choice} -eq 2 ]; then
        echo
    fi
}
remind1p() {
    if [ "$etag" == 1 ]; then
        echo -e "${MA}✘${NC}"
        etag=0
    else
        echo -e "${GR}●${NC}"
    fi
}
remind3p() {
    if [ "$etag" == 1 ]; then
        echo -e "${MA}✘ ✘ ✘${NC}"
        etag=0
    else
        echo -e "${GR}● ● ●${NC}"
    fi
}
waitfor() {
    echo -e "执行完成, ${NC}按${MA}任意键${NC}继续..."
    read -n 1 -s -r -p ""
}
virt_check() {
    cname=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
    virtualx=$(dmesg 2>/dev/null)
    if [ $(which dmidecode) ]; then
        sys_manu=$(dmidecode -s system-manufacturer 2>/dev/null)
        sys_product=$(dmidecode -s system-product-name 2>/dev/null)
        sys_ver=$(dmidecode -s system-version 2>/dev/null)
    else
        sys_manu=""
        sys_product=""
        sys_ver=""
    fi
    if grep docker /proc/1/cgroup -qa; then
        virtual="Docker"
    elif grep lxc /proc/1/cgroup -qa || grep -qa container=lxc /proc/1/environ; then
        virtual="Lxc"
    elif [ -f /proc/user_beancounters ]; then
        virtual="OpenVZ"
    elif [[ "$virtualx" == *kvm-clock* || "$cname" == *KVM* || "$cname" == *QEMU* ]]; then
        virtual="KVM"
    elif [[ "$virtualx" == *"VMware Virtual Platform"* ]]; then
        virtual="VMware"
    elif [[ "$virtualx" == *"Parallels Software International"* ]]; then
        virtual="Parallels"
    elif [[ "$virtualx" == *VirtualBox* ]]; then
        virtual="VirtualBox"
    elif [ -e /proc/xen ]; then
        virtual="Xen"
    elif [[ "$sys_manu" == *"Microsoft Corporation"* && "$sys_product" == *"Virtual Machine"* ]]; then
        if [[ "$sys_ver" == *"7.0"* || "$sys_ver" == *"Hyper-V"* ]]; then
            virtual="Hyper-V"
        else
            virtual="Microsoft Virtual Machine"
        fi
    else
        virtual="Dedicated"
    fi
}
# ipaddress=$(curl ifconfig.me)
get_random_color() {
    colors=($BL $RE $GR $YE $MA $CY $WH)  # Array of available colors
    random_index=$((RANDOM % ${#colors[@]}))
    echo "${colors[random_index]}"
}
text1="------------------------"
text2="============================"
colored_text1=""
colored_text2=""
for ((i=0; i<${#text1}; i++)); do
    color=$(get_random_color)
    colored_text1="${colored_text1}${color}${text1:$i:1}"
done

for ((i=0; i<${#text2}; i++)); do
    color=$(get_random_color)
    colored_text2="${colored_text2}${color}${text2:$i:1}"
done
if command -v apt &>/dev/null; then
    pm="apt"
elif command -v yum &>/dev/null; then
    pm="yum"
else
    echo "不支持的Linux包管理器"
    exit 1
fi
if ! command -v curl &>/dev/null || ! command -v wget &>/dev/null || ! command -v ifconfig &>/dev/null || ! command -v jq &>/dev/null; then
    clear_screen
    echo -e "${GR}▼${NC}"
    echo -e "${colored_text2}${NC}"
    echo -e "CURL/WGET/NET-TOOLS/JQ"
    read -e -p "检查到部分依赖工具没有安装, 是否要进行安装? (Y/其它跳过): " -n 3 -r choice
    if [[ $choice == "Y" || $choice == "y" ]]; then
        $pm install -y curl wget net-tools jq
    fi
fi
(EUID=$(id -u)) 2>/dev/null
virt_check
onlyone=1
while true; do
clear_screen
if [ "$EUID" -eq 0 ]; then
    user_path="/root"
else
    user_path="/home/$(whoami)"
    echo -e "${GR}当前用户为非root用户, 部分操作可能无法顺利进行.${NC}"
fi
echo -e "${RE}RedX 一键脚本工具 v1.0${NC}"
if [ "$virtual" != "" ]; then
    echo -e "VPS虚拟化类型: ${GR}$virtual${NC}"
fi
echo -e " ____  _____ ____  ${MA}__  __ ${NC}"
echo -e "|  _ \| ____|  _ \ ${MA}\ \/ / ${NC}"
echo -e "| |_) |  _| | | | | ${MA}\  /  ${NC}"
echo -e "|  _ <| |___| |_| | ${MA}/  \  ${NC}"
echo -e "|_| \_\_____|____ /${MA}/_/\_\ ${NC}"
echo -e "${BK}■ ${RE}■ ${GR}■ ${YE}■ ${BL}■ ${MA}■ ${CY}■ ${WH}■ ${BL}■ ${GR}■ ${BK}■"
echo -e "${colored_text2}${NC}"
echo -e "1.  XRAY  节点搭建相关操作 ▶"
echo -e "2.  ACME  证书申请相关操作 ▶"
echo -e "3.  BBR   相关操作 ▶"
echo -e "4.  WARP  相关操作 ▶"
echo -e "${colored_text1}${NC}"
echo -e "o.  更新脚本"
echo -e "x.  退出脚本"
echo -e "${colored_text1}${NC}"
if [[ $onlyone == 1 ]]; then
    echo -e "${MA}支持双击操作...${NC}"
else
    remind3p
fi
read -e -p "请输入你的选择: " -n 2 -r choice && echoo
case $choice in
    1|11)
        jsonfile="/usr/local/etc/xray/config.json"
        xrayactive=($(systemctl is-active xray.service | tr -d '\n'))
        # jsonfiletag=""
        # jsonfilen=0
        # if [ -f /usr/local/x-ui/bin/config.json ]; then
        #     jsonfile="/usr/local/x-ui/bin/config.json"
        #     jsonfiletag="X-UI"
        #     jsonfilen=$((jsonfilen+1))
        # fi
        # if [ -f /usr/local/etc/xray/config.json ]; then
        #     jsonfile="/usr/local/etc/xray/config.json"
        #     jsonfiletag="XRAY"
        #     jsonfilen=$((jsonfilen+1))
        # fi
        # if [ $jsonfilen -eq 2 ]; then
        #     while true; do
        #     echo "系统发现以下配置文件:"
        #     echo "1. XRAY官方脚本配置文件  2. XUI面板配置文件"
        #     read -e -p "请选择配置配置文件编号: " choice
        #     if [ $choice -eq 1 ]; then
        #         jsonfile="/usr/local/etc/xray/config.json"
        #         jsonfiletag="XRAY"
        #         break
        #     elif [ $choice -eq 2 ]; then
        #         jsonfile="/usr/local/x-ui/bin/config.json"
        #         jsonfiletag="X-UI"
        #         break
        #     else
        #         echo "请重新选择."
        #     fi
        #     done
        # fi
        # if [[ $jsonfilen -eq 0 ]]; then
        #     while true; do
        #     #echo -e "系统${MA}未发现${NC}配置文件:"
        #     echo "1. XRAY官方脚本  2. X-UI面板"
        #     read -e -p "请选择需要配置类型 (回车默认1.XRAY官方脚本): " choice
        #     if [[ $choice == "1" ]]; then
        #         jsonfile="/usr/local/etc/xray/config.json"
        #         jsonfiletag="XRAY"
        #         break
        #     elif [[ $choice == "2" ]]; then
        #         jsonfile="/usr/local/x-ui/bin/config.json"
        #         jsonfiletag="X-UI"
        #         break
        #     elif [[ $choice == "" ]]; then
        #         jsonfile="/usr/local/etc/xray/config.json"
        #         jsonfiletag="XRAY"
        #         break
        #     else
        #         echo "请重新选择."
        #     fi
        #     done
        # fi

        makejsonfile() {
            jq -n '{
                "log": {
                    "loglevel": "warning",
                    "access": "/var/log/xray/access.log",
                    "error": "/var/log/xray/error.log"
                },
                "api": {
                    "tag": "api",
                    "services": [
                        "HandlerService",
                        "LoggerService",
                        "StatsService"
                    ]
                },
                "dns": {
                    "tag": "dns_inbound",
                    "hosts": {},
                    "servers": [
                        "8.8.8.8",
                        "1.1.1.1"
                    ]
                },
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [
                        {
                            "type": "field",
                            "outboundTag": "common",
                            "network": "udp,tcp"
                        },
                        {
                            "type": "field",
                            "outboundTag": "blocked",
                            "ip": [
                                "geoip:cn",
                                "geoip:private"
                            ],
                            "protocol": [
                                "bittorrent"
                            ]
                        }
                    ]
                },
                "policy": {
                    "system": {
                        "statsInboundUplink": true,
                        "statsInboundDownlink": true
                    },
                    "levels": {
                        "0": {
                            "handshake": 5,
                            "connIdle": 200,
                            "uplinkOnly": 2,
                            "downlinkOnly": 5,
                            "bufferSize": 10240
                        }
                    }
                },
                "inbounds": [],
                "outbounds": [
                    {
                        "tag": "common",
                        "protocol": "freedom"
                    },
                    {
                        "tag": "blocked",
                        "protocol": "blackhole",
                        "settings": {}
                    }
                ],
                "stats": null,
                "reverse": null,
                "transport": null,
                "fakeDns": null
            }' > $jsonfile
                echo "文件 $jsonfile 创建成功."
            }
        #############################################
        #jsonfile="/usr/local/etc/xray/config.json"
        #jsonfile="$user_path/new.json" ### new.json for test

        if [ ! -e "$jsonfile" ]; then
            read -e -p "config.json配置文件不存在。是否创建? (Y/其它跳过): " create
            if [ "$create" = "y" ] || [ "$create" = "Y" ]; then
                touch $jsonfile
                makejsonfile
                waitfor
            else
                #echo "没有指定config.json配置文件, 脚本无法顺利执行."
                waitfor
                continue
            fi
        fi
        if [[ $(cat $jsonfile | wc -l) -eq 1 ]]; then
            read -e -p "文件未初始化, 是否要初始化 JSON 文件? (Y/其它取消): " create
            if [ "$create" = "y" ] || [ "$create" = "Y" ]; then
                makejsonfile
                waitfor
            else
                echo "未初始化文件, 脚本无法顺利执行."
                waitfor
                continue
            fi
        fi

        while true; do
        xtag=""
        if ! command -v jq &>/dev/null; then
            xtag="${YE}*${NC}"
        fi
        if command -v xray &>/dev/null; then
            #xrayver=$(xray version | head -n 1 | awk '{print $1, $2}')
            xrayver=$(xray version | head -n 1 | awk '{print $2}')
        else
            xrayver="未安装"
            xtag="${MA}*${NC}"
        fi
        clear_screen
        echo -e "${GR}▼▼${NC}"
        echo -e "${GR}XRAY${NC}         版本: ${MA}$xrayver${NC}"
        echo -e "${colored_text2}${NC}"
        echo -e "1.  创建节点"
        echo -e "2.  查询节点明细"
        echo -e "3.  修改节点"
        echo -e "4.  删除节点"
        echo -e "${colored_text1}${NC}"
        echo -e "5.  手动编辑配置文件"
        echo -e "${colored_text1}${NC}"
        echo -e "8.  启动/重启 XRAY 服务"
        echo -e "9.  停止 XRAY 服务"
        echo -e "${colored_text1}${NC}"
        echo -e "v.  查询 XRAY 状态   ${MA}$xrayactive${NC}"
        echo -e "l.  查询 XRAY 运行日志"
        echo -e "${colored_text1}${NC}"
        echo -e "i.  安装/更新 XRAY 官方脚本 $xtag"
        echo -e "u.  更新 geodata 文件"
        echo -e "d.  删除 XRAY 官方脚本"
        echo -e "${colored_text1}${NC}"
        echo -e "r.  返回主菜单"
        echo -e "x.  退出脚本"
        echo -e "${colored_text1}${NC}"
        remind3p
        read -e -p "请输入你的选择: " -n 2 -r choice && echoo
        case $choice in
            1|11)
                uuid=$(xray uuid)
                short_chars="0123456789abcdef"
                short_id_length=8
                short_id=""
                for (( i = 0; i < short_id_length; i++ )); do
                    short_id+=${short_chars:$RANDOM%16:1}
                done
                while true; do
                en_protocol=""
                en_port=""
                en_trojan_password=""
                en_network=""
                en_security=""
                en_tls_flow=""
                en_tls_serverName=""
                en_tls_certificateFile=""
                en_tls_keyFile=""
                en_http_path=""
                en_http_head=""
                en_reality_dest=""
                en_reality_serverNames=""
                en_reality_fingerprint=""
                en_reality_privateKey=""
                en_reality_publicKey=""
                en_reality_shortIds=""
                echo -e "${colored_text1}${NC}"
                while true; do
                remind1p
                echo "节点类型: 1.Vmess  2.Vless  3.Trojan  4.Shadowsocks  5.dokodemo-door  6.socks  7.http"
                read -e -p "请先择创建节点类型 (1/2/3/4/5/6/7/C取消): " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        en_protocol="vmess"
                        break
                        ;;
                    2|22)
                        en_protocol="vless"
                        break
                        ;;
                    3|33)
                        en_protocol="trojan"
                        break
                        ;;
                    4|44)
                        en_protocol="shadowsocks"
                        break
                        ;;
                    5|55)
                        en_protocol="dokodemo-door"
                        break
                        ;;
                    6|66)
                        en_protocol="socks"
                        break
                        ;;
                    7|77)
                        en_protocol="http"
                        break
                        ;;
                    c|cc|C|CC)
                        break 2
                        ;;
                    *)
                        etag=1
                        ;;
                esac
                done
                while true; do
                echo -e "${colored_text1}${NC}"
                remind1p
                port_con=0
                echo "使用中的端口:"
                check_port_array=($(jq '.inbounds[] | .port' "$jsonfile"))
                for check_port in "${check_port_array[@]}"; do
                    echo "$check_port"
                done
                echo "端口范围: 1-65535, 请自行规避其它程序占用的端口."
                read -e -p "请输入端口号: " number
                if [[ $number =~ ^[0-9]+$ && $number -ge 1 && $number -le 65535 ]]; then
                    for check_port in "${check_port_array[@]}"; do
                    if [[ $check_port -eq $number ]]; then
                        echo "端口 $number 已经被使用, 请重新输入."
                        port_con=1
                        break
                    fi
                    done
                    if [[ ! $port_con -eq 1 ]]; then
                        en_port=$number
                        break 1
                    fi
                fi
                etag=1
                done
                if [[ $en_protocol == "trojan" ]]; then
                    while true; do
                        random=$((100000 + RANDOM % 900000))
                        echo -e "${colored_text1}${NC}"
                        remind1p
                        read -e -p "请设置Trojan密码 (回车默认: 系统生成): " password
                            if [[ $password == "" ]]; then
                                en_trojan_password="$random"
                                break
                            else
                                en_trojan_password="$password"
                                break
                            fi
                    done
                fi
                if [[ $en_protocol == "vmess" || $en_protocol == "vless" || $en_protocol == "trojan" || $en_protocol == "shadowsocks" ]]; then
                    echo -e "${colored_text1}${NC}"
                    while true; do
                    remind1p
                    echo "传输协议类型: 1.tcp  2.kcp  3.ws  4.http  5.quic  6.grpc"
                    read -e -p "请先择 (1/2/3/4/5/6/C取消): " -n 2 -r choice && echoo
                    case $choice in
                        1|11)
                            en_network="tcp"
                            break
                            ;;
                        2|22)
                            en_network="kcp"
                            break
                            ;;
                        3|33)
                            en_network="ws"
                            break
                            ;;
                        4|44)
                            en_network="http"
                            break
                            ;;
                        5|55)
                            en_network="quic"
                            break
                            ;;
                        6|66)
                            en_network="grpc"
                            break
                            ;;
                        c|cc|C|CC)
                            break 2
                            ;;
                        *)
                            etag=1
                            ;;
                    esac
                    done
                    if [[ $en_network == "tcp" ]]; then
                        echo -e "${colored_text1}${NC}"
                        while true; do
                        remind1p
                        echo "传输层安全类型: 1.tls  2.http  3.reality  0.不使用"
                        read -e -p "请先择 (1/2/3/0/C取消): " -n 2 -r choice && echoo
                        case $choice in
                            1|11)
                                en_security="tls"
                                break
                                ;;
                            2|22)
                                en_security="http"
                                break
                                ;;
                            3|33)
                                if [[ $en_protocol == "vless" && $en_network == "tcp" ]] || [[ $en_protocol == "trojan" && $en_network == "tcp" ]]; then
                                    en_security="reality"
                                    break
                                else
                                    echo -e "注意, 只有当协议为${MA}Vless${NC}或${MA}Trojan${NC}的时候才能使用Reality传输."
                                    etag=1
                                fi
                                ;;
                            0)
                                en_security=""
                                break
                                ;;
                            c|cc|C|CC)
                                break 2
                                ;;
                            *)
                                etag=1
                                ;;
                        esac
                        done
                    fi
                    if [[ $en_network == "kcp" ]]; then
                        :
                    fi
                    if [[ $en_network == "ws" ]]; then
                        read -e -p "请输入WS-PATH (格式: /path)(回车默认./): " path
                        if [[ $path != "" ]]; then
                            en_ws_path="$path"
                        else
                            en_ws_path="/"
                        fi
                        read -e -p "请输入WS-HOST (回车.无): " host
                        if [[ $host != "" ]]; then
                            en_ws_host="$host"
                        else
                            en_ws_host=""
                        fi
                    fi
                    if [[ $en_network == "http" ]]; then
                        read -e -p "请输入http-PATH (格式: /path)(回车默认./): " path
                        if [[ $path != "" ]]; then
                            en_http_path="$path"
                        else
                            en_http_path="/"
                        fi
                        read -e -p "请输入http-HOST (回车.无): " host
                        if [[ $host != "" ]]; then
                            en_http_host="$host"
                        else
                            en_http_host=""
                        fi
                    fi
                    if [[ $en_network == "quic" ]]; then
                        :
                    fi
                    if [[ $en_network == "grpc" ]]; then
                        :
                    fi
                    if [[ $en_protocol == "vless" && $en_network == "tcp" && $en_security == "tls" ]] || [[ $en_protocol == "vless" && $en_network == "tcp" && $en_security == "reality" ]]; then
                        echo -e "流控flow方式 :  1.xtls-rprx-vision  0/其它.无"
                        read -e -p "请选择流控flow方式编号 : " choice
                        if [[ $choice == 1 ]]; then
                            en_tls_flow="xtls-rprx-vision"
                        else
                            en_tls_flow=""
                        fi
                    fi
                    if [[ $en_security == "tls" ]]; then
                        echo -e "${colored_text1}${NC}"
                        remind1p
                        read -e -p "请输入tls域名: " url
                        en_tls_serverName="$url"
                        read -e -p "请输入公钥文件路径: " url
                        en_tls_certificateFile="$url"
                        read -e -p "请输入密钥文件路径: " url
                        en_tls_keyFile="$url"
                    fi
                    if [[ $en_security == "http" ]]; then
                        echo -e "${colored_text1}${NC}"
                        remind1p
                        read -e -p "请输入请求路径: " url
                        en_http_path="$url"
                        read -e -p "请输入请求头: " url
                        en_http_head="$url"
                    fi
                    if [[ $en_security == "reality" ]]; then
                        echo -e "${colored_text1}${NC}"
                        remind1p
                        read -e -p "请输入dest地址(带端口) (回车默认: www.yahoo.com:443): " url
                        if [[ $url == "" ]]; then
                            en_reality_dest="www.yahoo.com:443"
                        else
                            en_reality_dest="$url"
                        fi
                        read -e -p "请输入serverNames地址 (回车默认: www.yahoo.com): " url
                        if [[ $url == "" ]]; then
                            en_reality_serverNames="www.yahoo.com"
                        else
                            en_reality_serverNames="$url"
                        fi
                        echo -e "请选择fingerprint: 1.chrome  2.firefox  3.safari  4.edge  5.ios  6.android"
                        read -e -p "请输入fingerprint编号: (回车默认: chrome): " choice
                        case $choice in
                        1|11)
                            en_reality_fingerprint="chrome"
                            ;;
                        2|22)
                            en_reality_fingerprint="firefox"
                            ;;
                        3|33)
                            en_reality_fingerprint="safari"
                            ;;
                        4|44)
                            en_reality_fingerprint="edge"
                            ;;
                        5|55)
                            en_reality_fingerprint="ios"
                            ;;
                        6|66)
                            en_reality_fingerprint="android"
                            ;;
                        "")
                            en_reality_fingerprint="chrome"
                            ;;
                        *)
                            etag=1
                            break
                            ;;
                        esac
                        read -e -p "请输入privateKey (回车默认: 系统生成): " url
                        if [[ $url == "" ]]; then
                            en_reality_privateKey=$(echo "$(xray x25519)" | sed -n 's/Private key: \(.*\)/\1/p')
                        else
                            en_reality_privateKey="$url"
                        fi
                        read -e -p "请输入publicKey (回车默认: 系统生成): " url
                        if [[ $url == "" ]]; then
                            en_reality_publicKey=$(echo "$(xray x25519)" | sed -n 's/Public key: \(.*\)/\1/p')
                        else
                            en_reality_publicKey="$url"
                        fi
                        read -e -p "请输入shortIds (回车默认: 系统生成): " url
                        if [[ $url == "" ]]; then
                            en_reality_shortIds=$short_id
                        else
                            en_reality_shortIds="$url"
                        fi
                    fi
                fi

                echo -e "${colored_text1}${NC}"
                echo -e "${GR}信息确认${NC}"
                echo -e "${CY}节点类型:${NC}      $en_protocol"
                echo -e "${CY}占用端口:${NC}      $en_port"
                if [[ $en_protocol == "trojan" ]]; then
                    echo -e "${CY}密码:${NC}          $en_trojan_password"
                fi
                if [[ $en_protocol == "vmess" || $en_protocol == "vless" ]]; then
                    echo -e "${CY}UUID:${NC}          $uuid"
                fi
                echo -e "${CY}传输协议:${NC}      $en_network"
                if [[ $en_tls_flow != "" ]]; then
                    echo -e "${CY}流控FLOW:${NC}      $en_tls_flow"
                fi
                echo -e "${CY}安全加密:${NC}      $en_security"
                if [[ $en_security == "tls" ]]; then
                    echo -e "${CY}TLS域名:${NC}       $en_tls_serverName"
                    echo -e "${CY}公钥文件路径:${NC}  $en_tls_certificateFile"
                    echo -e "${CY}密钥文件路径:${NC}  $en_tls_keyFile"
                fi
                if [[ $en_security == "reality" ]]; then
                    echo -e "${CY}dest:${NC}          $en_reality_dest"
                    echo -e "${CY}serverNames:${NC}   $en_reality_serverNames"
                    echo -e "${CY}fingerprint:${NC}   $en_reality_fingerprint"
                    echo -e "${CY}privateKey:${NC}    $en_reality_privateKey"
                    echo -e "${CY}publicKey:${NC}     $en_reality_publicKey"
                    echo -e "${CY}shortIds:${NC}      $en_reality_shortIds"
                fi
                echo "..."
                while true; do
                read -e -p "请确认信息，是否决定创建? (Y/C取消): " choice
                
                if [[ $choice == "Y" || $choice == "y" ]]; then

                    echo "创建执行中..."
                    # 新对象的内容
                    new_inbound='{
                    "listen": null,
                    "port": null,
                    "protocol": null,
                    "settings": {
                        "clients": [
                            {
                                "id": null,
                                "flow": null
                            }
                        ],
                        "decryption": "none",
                        "fallbacks": []
                    },
                    "streamSettings": {
                        "network": null,
                        "security": null,
                        "tlsSettings": {
                            "serverName": null,
                            "minVersion": "1.2",
                            "maxVersion": "1.3",
                            "cipherSuites": "",
                            "certificates": [
                                {
                                "ocspStapling": 3600
                                }
                            ],
                            "alpn": [
                                "http/1.1",
                                "h2"
                            ],
                            "settings": [
                                {
                                "allowInsecure": false,
                                "fingerprint": "",
                                "serverName": ""
                                }
                            ]
                        },
                        "realitySettings": {
                            "show": false,
                            "fingerprint": null,
                            "dest": null,
                            "xver": 0,
                            "serverNames": [
                            ],
                            "privateKey": null,
                            "publicKey": null,
                            "minClientVer": "",
                            "maxClientVer": "",
                            "maxTimeDiff": 0,
                            "shortIds": [
                            ]
                        },
                        "tcpSettings": {
                            "acceptProxyProtocol": false,
                            "header": {
                                "type": "none"
                            }
                        }
                    },
                    "tag": null,
                    "sniffing": {
                        "enabled": true,
                        "destOverride": [
                        "http",
                        "tls",
                        "quic"
                        ]
                    }
                    }'

                    # 在.json文件中的.inbounds[]数组中添加新的对象
                    jq ".inbounds += [$new_inbound]" "$jsonfile" > temp.json && mv temp.json "$jsonfile"

                    # 添加新对象到 .inbounds[] 数组
                    jq --argjson en_port "$en_port" \
                    --arg en_protocol "$en_protocol" \
                    --arg en_network "$en_network" \
                    '.inbounds[-1].port = $en_port |
                    .inbounds[-1].protocol = $en_protocol |
                    .inbounds[-1].tag = "inbound-\($en_port)" |
                    .inbounds[-1].streamSettings.network = $en_network' \
                    "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    jq --arg uuid "$uuid" \
                    '.inbounds[-1].settings.clients[0].id = $uuid' \
                    "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    if [[ $en_tls_flow != "" ]]; then
                        jq --arg en_tls_flow "$en_tls_flow" \
                        '.inbounds[-1].settings.clients[0].flow = $en_tls_flow' \
                        "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    fi
                    if [[ $en_security != "" ]]; then
                        jq --arg en_security "$en_security" \
                        '.inbounds[-1].streamSettings.security = $en_security' \
                        "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    fi
                    if [[ $en_security == "tls" ]]; then
                        jq --arg en_tls_serverName "$en_tls_serverName" \
                        --arg en_tls_certificateFile "$en_tls_certificateFile" \
                        --arg en_tls_keyFile "$en_tls_keyFile" \
                        'del(.inbounds[-1].streamSettings.realitySettings) |
                        .inbounds[-1].streamSettings.tlsSettings.serverName = $en_tls_serverName |
                        .inbounds[-1].streamSettings.tlsSettings.certificates[0].certificateFile = $en_tls_certificateFile |
                        .inbounds[-1].streamSettings.tlsSettings.certificates[0].keyFile = $en_tls_keyFile' \
                        "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    fi
                    if [[ $en_security == "reality" ]]; then
                        jq --arg en_reality_dest "$en_reality_dest" \
                        --arg en_reality_serverNames "$en_reality_serverNames" \
                        --arg en_reality_fingerprint "$en_reality_fingerprint" \
                        --arg en_reality_privateKey "$en_reality_privateKey" \
                        --arg en_reality_publicKey "$en_reality_publicKey" \
                        --arg en_reality_shortIds "$en_reality_shortIds" \
                        'del(.inbounds[-1].streamSettings.tlsSettings) |
                        .inbounds[-1].streamSettings.realitySettings.dest = $en_reality_dest |
                        .inbounds[-1].streamSettings.realitySettings.serverNames[0] = $en_reality_serverNames |
                        .inbounds[-1].streamSettings.realitySettings.fingerprint = $en_reality_fingerprint |
                        .inbounds[-1].streamSettings.realitySettings.privateKey = $en_reality_privateKey |
                        .inbounds[-1].streamSettings.realitySettings.publicKey = $en_reality_publicKey |
                        .inbounds[-1].streamSettings.realitySettings.shortIds[0] = $en_reality_shortIds' \
                        "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    fi

                    cat $jsonfile

                    # 读取JSON文件中的变量值，并将变量名前缀改成rd_   (这里只读取一个值，后期需要全部读取出来（改成数组）)**********
                    rd_port=$(jq -r '.inbounds[-1].port' "$jsonfile")
                    rd_protocol=$(jq -r '.inbounds[-1].protocol' "$jsonfile")
                    rd_network=$(jq -r '.inbounds[-1].streamSettings.network' "$jsonfile")
                    rd_security=$(jq -r '.inbounds[-1].streamSettings.security' "$jsonfile")
                    rd_tls_serverName=$(jq -r '.inbounds[-1].streamSettings.tlsSettings.serverName' "$jsonfile")
                    rd_tls_certificateFile=$(jq -r '.inbounds[-1].streamSettings.tlsSettings.certificates[0].certificateFile' "$jsonfile")
                    rd_tls_keyFile=$(jq -r '.inbounds[-1].streamSettings.tlsSettings.certificates[0].keyFile' "$jsonfile")
                    rd_reality_dest=$(jq -r '.inbounds[-1].streamSettings.realitySettings.dest' "$jsonfile")
                    rd_reality_serverNames=$(jq -r '.inbounds[-1].streamSettings.realitySettings.serverNames[0]' "$jsonfile")
                    rd_reality_fingerprint=$(jq -r '.inbounds[-1].streamSettings.realitySettings.fingerprint' "$jsonfile")
                    rd_reality_privateKey=$(jq -r '.inbounds[-1].streamSettings.realitySettings.privateKey' "$jsonfile")
                    rd_reality_publicKey=$(jq -r '.inbounds[-1].streamSettings.realitySettings.publicKey' "$jsonfile")
                    rd_reality_shortIds=$(jq -r '.inbounds[-1].streamSettings.realitySettings.shortIds[0]' "$jsonfile")
                    # 输出读取到的变量值（仅供参考，你可以根据需要使用这些变量）
                    echo "端口号: $rd_port"
                    echo "协议类型: $rd_protocol"
                    echo "网络类型: $rd_network"
                    echo "安全性设置: $rd_security"
                    echo "TLS服务器名: $rd_tls_serverName"
                    echo "TLS证书文件路径: $rd_tls_certificateFile"
                    echo "TLS私钥文件路径: $rd_tls_keyFile"
                    echo "reality_dest: $rd_reality_dest"
                    echo "reality_serverNames: $rd_reality_serverNames"
                    echo "reality_fingerprint: $rd_reality_fingerprint"
                    echo "reality_privateKey: $rd_reality_privateKey"
                    echo "reality_publicKey: $rd_reality_publicKey"
                    echo "reality_shortIds: $rd_reality_shortIds"

                    waitfor
                    break
                elif [[ $choice == "C" || $choice == "c" ]]; then
                    break
                fi
                done
                break
                done
                ;;

            2|22)
                clear_screen

                # 读取JSON文件中的变量值，并将变量名前缀改成rd_，将变量改为数组
                mapfile -t rd_port < <(jq -r '.inbounds[].port' "$jsonfile")
                mapfile -t rd_protocol < <(jq -r '.inbounds[].protocol' "$jsonfile")
                mapfile -t rd_network < <(jq -r '.inbounds[].streamSettings.network' "$jsonfile")
                mapfile -t rd_security < <(jq -r '.inbounds[].streamSettings.security' "$jsonfile")
                mapfile -t rd_tls_serverName < <(jq -r '.inbounds[].streamSettings.tlsSettings.serverName' "$jsonfile")
                mapfile -t rd_tls_certificateFile < <(jq -r '.inbounds[].streamSettings.tlsSettings.certificates[0].certificateFile' "$jsonfile")
                mapfile -t rd_tls_keyFile < <(jq -r '.inbounds[].streamSettings.tlsSettings.certificates[0].keyFile' "$jsonfile")
                mapfile -t rd_reality_dest < <(jq -r '.inbounds[].streamSettings.realitySettings.dest' "$jsonfile")
                mapfile -t rd_reality_serverNames < <(jq -r '.inbounds[].streamSettings.realitySettings.serverNames[0]' "$jsonfile")
                mapfile -t rd_reality_fingerprint < <(jq -r '.inbounds[].streamSettings.realitySettings.fingerprint' "$jsonfile")
                mapfile -t rd_reality_privateKey < <(jq -r '.inbounds[].streamSettings.realitySettings.privateKey' "$jsonfile")
                mapfile -t rd_reality_publicKey < <(jq -r '.inbounds[].streamSettings.realitySettings.publicKey' "$jsonfile")
                mapfile -t rd_reality_shortIds < <(jq -r '.inbounds[].streamSettings.realitySettings.shortIds[0]' "$jsonfile")
                mapfile -t rd_tag < <(jq -r '.inbounds[].tag' "$jsonfile")
                mapfile -t rd_client_id < <(jq -r '.inbounds[].settings.clients[0].id' "$jsonfile")
                mapfile -t rd_client_flow < <(jq -r '.inbounds[].settings.clients[0].flow' "$jsonfile")

                # 遍历数组，输出读取到的变量值，仅当变量不为空时才显示
                echo -e "${GR}▼▼${NC}"                  
                for ((i=0; i<${#rd_port[@]}; i++)); do
                    echo -e "${colored_text1}${NC}"
                    echo "节点 $((i+1))"
                    
                    if [ -n "${rd_port[i]}" ] && [ "${rd_port[i]}" != "null" ]; then
                        echo "端口号: ${rd_port[i]}"
                    fi

                    if [ -n "${rd_protocol[i]}" ] && [ "${rd_protocol[i]}" != "null" ]; then
                        echo "协议类型: ${rd_protocol[i]}"
                    fi

                    if [ -n "${rd_client_id[i]}" ] && [ "${rd_client_id[i]}" != "null" ]; then
                        echo "客户端ID: ${rd_client_id[i]}"
                    fi

                    if [ -n "${rd_client_flow[i]}" ] && [ "${rd_client_flow[i]}" != "null" ]; then
                        echo "客户端流量: ${rd_client_flow[i]}"
                    fi

                    if [ -n "${rd_network[i]}" ] && [ "${rd_network[i]}" != "null" ]; then
                        echo "网络类型: ${rd_network[i]}"
                    fi

                    if [ -n "${rd_security[i]}" ] && [ "${rd_security[i]}" != "null" ]; then
                        echo "安全性设置: ${rd_security[i]}"
                    fi

                    if [ -n "${rd_tls_serverName[i]}" ] && [ "${rd_tls_serverName[i]}" != "null" ]; then
                        echo "TLS服务器名: ${rd_tls_serverName[i]}"
                    fi

                    if [ -n "${rd_tls_certificateFile[i]}" ] && [ "${rd_tls_certificateFile[i]}" != "null" ]; then
                        echo "TLS证书文件路径: ${rd_tls_certificateFile[i]}"
                    fi

                    if [ -n "${rd_tls_keyFile[i]}" ] && [ "${rd_tls_keyFile[i]}" != "null" ]; then
                        echo "TLS私钥文件路径: ${rd_tls_keyFile[i]}"
                    fi

                    if [ -n "${rd_reality_dest[i]}" ] && [ "${rd_reality_dest[i]}" != "null" ]; then
                        echo "reality_dest: ${rd_reality_dest[i]}"
                    fi

                    if [ -n "${rd_reality_serverNames[i]}" ] && [ "${rd_reality_serverNames[i]}" != "null" ]; then
                        echo "reality_serverNames: ${rd_reality_serverNames[i]}"
                    fi

                    if [ -n "${rd_reality_fingerprint[i]}" ] && [ "${rd_reality_fingerprint[i]}" != "null" ]; then
                        echo "reality_fingerprint: ${rd_reality_fingerprint[i]}"
                    fi

                    if [ -n "${rd_reality_privateKey[i]}" ] && [ "${rd_reality_privateKey[i]}" != "null" ]; then
                        echo "reality_privateKey: ${rd_reality_privateKey[i]}"
                    fi

                    if [ -n "${rd_reality_publicKey[i]}" ] && [ "${rd_reality_publicKey[i]}" != "null" ]; then
                        echo "reality_publicKey: ${rd_reality_publicKey[i]}"
                    fi

                    if [ -n "${rd_reality_shortIds[i]}" ] && [ "${rd_reality_shortIds[i]}" != "null" ]; then
                        echo "reality_shortIds: ${rd_reality_shortIds[i]}"
                    fi
                done

                i_protocol=".protocol"
                i_port=".port"
                i_id=".settings.clients[0].id"
                i_network=".streamSettings.network"
                i_security=".streamSettings.security"
                i_tls_flow=".settings.clients[0].flow"
                i_tls_serverName=".streamSettings.tlsSettings.serverName"
                i_tls_certificateFile=".streamSettings.tlsSettings.certificates[0].certificateFile"
                i_tls_keyFile=".streamSettings.tlsSettings.certificates[0].keyFile"
                i_reality_dest=".streamSettings.realitySettings.dest"
                i_reality_fingerprint=".streamSettings.realitySettings.fingerprint"
                i_reality_serverNames=".streamSettings.realitySettings.serverNames[0]"
                i_reality_privateKey=".streamSettings.realitySettings.privateKey"
                i_reality_publicKey=".streamSettings.realitySettings.publicKey"
                i_reality_shortIds=".streamSettings.realitySettings.shortIds[0]"
                i_ws_path=".streamSettings.wsSettings.path"
                i_ws_host=".streamSettings.wsSettings.headers.Host"

                echo -e "${colored_text2}${NC}"
                waitfor
                ;;
            3|33)
                echo -e "${colored_text1}${NC}"
                echo -e "${CY}节点${NC}   ${CY}协议${NC}       ${CY}端口${NC}"
                protocols=( $(jq -r '.inbounds[].protocol' "$jsonfile") )
                ports=( $(jq -r '.inbounds[].port' "$jsonfile") )
                for ((i=0; i<${#protocols[@]}; i++)); do
                    echo "▶ $((i+1))    ${protocols[i]}      ${ports[i]}"
                done
                echo -e "${colored_text1}${NC}"
                echo "制作中..."
                waitfor
                ;;
            4|44)
                echo -e "${colored_text1}${NC}"
                echo -e "${CY}节点${NC}   ${CY}协议${NC}       ${CY}端口${NC}"
                protocols=( $(jq -r '.inbounds[].protocol' "$jsonfile") )
                ports=( $(jq -r '.inbounds[].port' "$jsonfile") )
                for ((i=0; i<${#protocols[@]}; i++)); do
                    echo "▶ $((i+1))    ${protocols[i]}      ${ports[i]}"
                done
                echo -e "${colored_text1}${NC}"
                read -e -p "请输入要删除的节点序号: " choice
                if [[ $choice != "" ]]; then
                    length=$(jq '.inbounds | length' "$jsonfile")
                    jq "del(.inbounds[$choice-1])" "$jsonfile" > temp.json && mv temp.json "$jsonfile"
                    new_length=$(jq '.inbounds | length' "$jsonfile")
                    if [[ $new_length -eq $((length - 1)) ]]; then
                        echo "节点已删除成功."
                        waitfor
                    else
                        echo -e "节点删除${MA}失败${NC}."
                        waitfor
                    fi
                else
                etag=1
                fi
                ;;
            5|55)
                nano $jsonfile
                waitfor
                ;;
            8|88)
                systemctl restart xray.service
                waitfor
                ;;
            9|99)
                systemctl stop xray.service
                waitfor
                ;;
            v|vv|V|VV)
                systemctl status xray.service
                waitfor
                ;;
            l|ll|L|LL)
                journalctl -u xray
                waitfor
                ;;
            i|ii|I|II)
                bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
                # mkdir -p /usr/local/etc/xray
                # mkdir -p /var/log/xray
                # if [ ! -e "/var/log/xray/access.log" ]; then
                #     touch /var/log/xray/access.log
                # fi
                # if [ ! -e "/var/log/xray/error.log" ]; then
                #     touch /var/log/xray/error.log
                # fi
                # chown -R nobody /var/log/xray
                # sed -i "s/User=.*/User=$(whoami)/" "/etc/systemd/system/xray.service"
                # systemctl daemon-reload
                if ! command -v jq &>/dev/null; then
                    $pm -y install jq
                fi
                waitfor
                ;;
            u|U|uu|UU)
                bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata
                waitfor
                ;;
            d|D|dd|DD)
                bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
                read -e -p "是否要删除所有残留(包括配置文件)? (Y/其它跳过): " choice
                if [[ $choice == "Y" || $choice == "y" ]]; then
                    rm -rf /usr/local/etc/xray
                    rm -rf /var/log/xray
                    waitfor
                fi
                ### 以下两行为删除/tmp下所有带xray关健定的文件或文件夹 (额外添加, 可以去除)
                # find /tmp -type f -name "*xray*" -exec rm -f {} +
                # find /tmp -type d -name "*xray*" -exec rm -rf {} +
                ;;
            r|R|rr|RR)
                break
                ;;
            x|X|xx|XX)
                exit 0
                ;;
            *)
                etag=1
                ;;
        esac
        done
        onlyone=0
        ;;
    2|22)
        while true; do
        if [ -x "$user_path/.acme.sh/acme.sh" ]; then
            acmever=$($user_path/.acme.sh/acme.sh --version | sed -n '2p' | awk '{print $1}')
        else
            acmever="未安装"
            acmetag="*"
        fi
        clear_screen
        echo -e "${GR}▼▼${NC}"
        echo -e "${GR}ACME${NC}          ${MA}$acmever${NC}"
        echo -e "${colored_text2}${NC}"
        echo -e "1.  申请证书"
        echo -e "2.  查询证书"
        echo -e "3.  更新证书"
        echo -e "4.  删除证书"
        echo -e "${colored_text1}${NC}"
        echo -e "i.  安装/更新 ACME 官方脚本 ${MA}$acmetag${NC}"
        echo -e "d.  删除 ACME 官方脚本"
        echo -e "${colored_text1}${NC}"
        echo -e "r.  返回主菜单"
        echo -e "x.  退出脚本"
        echo -e "${colored_text1}${NC}"
        remind3p
        read -e -p "请输入你的选择: " -n 2 -r choice && echoo
        case $choice in
            1|11)
                if [ ! -d $user_path/cert ]; then
                    mkdir $user_path/cert
                fi
                while true; do
                random=$((100000 + RANDOM % 900000))
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 申请证书${NC}"
                echo -e "${colored_text2}${NC}"
                echo -e "1.  方法一: 采用端口 80 验证方式申请"
                echo -e "2.  方法二: 采用 Nginx 验证方式申请 (需要安装Nginx)"
                echo -e "3.  方法三: 采用 http 绝对路径方式验证申请"
                echo -e "4.  方法四: 采用 cloudflare 的 API 验证方式申请"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                echo -e "${MA}注${NC}: 证书申请成功后将自动保存至: ${GR}$user_path/cert${NC} 文件夹中"
                echo -e "${colored_text1}${NC}"
                remind3p
                read -e -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        while true; do
                            read -e -p "请输入申请证书的域名: " domain
                            if [[ $domain == *.* ]]; then
                                pids=$(lsof -t -i :80)
                                if [ -n "$pids" ]; then
                                    for pid in $pids; do
                                        kill -9 $pid &>/dev/null
                                    done
                                fi
                                $user_path/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                $user_path/.acme.sh/acme.sh --issue -d $domain --standalone
                                $user_path/.acme.sh/acme.sh --installcert -d $domain --key-file $user_path/cert/$domain.key --fullchain-file $user_path/cert/$domain.cer
                                if [ ! -s "$user_path/cert/$domain.key" ] && [ ! -s "$user_path/cert/$domain.cer" ]; then
                                    rm $user_path/cert/$domain.key &>/dev/null
                                    rm $user_path/cert/$domain.cer &>/dev/null
                                    rm -rf $user_path/.acme.sh/${domain}_ecc &>/dev/null
                                fi
                                if [[ -f "$user_path/cert/$domain.key" && -f "$user_path/cert/$domain.cer" ]]; then
                                    echo "证书已生成并保存到 $user_path/cert 目录下."
                                    break
                                fi
                                echo "证书生成失败."
                                break
                            else
                                if [[ $domain == "" ]]; then
                                    break
                                fi
                                echo "输入的域名不合法, 请重新输入."
                            fi
                        done
                        waitfor
                        ;;
                    2|22)
                        while true; do
                            read -e -p "请输入申请证书的域名: " domain
                            if [[ $domain == *.* ]]; then
                                pids=$(lsof -t -i :80)
                                if [ -n "$pids" ]; then
                                    for pid in $pids; do
                                        kill -9 $pid
                                    done
                                fi
                                if ! command -v nginx &>/dev/null; then
                                    read -e -p "系统未检测到Nginx, 是否进行Nginx安装 (Y/其它跳过): " choice
                                    if [[ ! $choice == "Y" && ! $choice == "y" ]]; then
                                        break
                                    fi
                                    $pm -y install nginx
                                fi
                                if [[ ! -f "/etc/nginx/nginx.redx" ]]; then
                                    cp /etc/nginx/nginx.conf /etc/nginx/nginx.redx
                                fi
                                cp /etc/nginx/nginx.conf /etc/nginx/nginx_bak.conf
                                write_conf() {
                                    echo "user www-data;
                                    events {
                                        worker_connections 768;
                                    }
                                    http {
                                        server {
                                        listen 80 default_server;
                                        listen [::]:80 default_server;
                                        root /var/www/html;
                                        index index.html index.htm index.nginx-debian.html;
                                        server_name $domain;
                                        }
                                    }" > /etc/nginx/nginx.conf
                                    systemctl start nginx
                                    $user_path/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                    $user_path/.acme.sh/acme.sh --issue -d $domain --nginx
                                    $user_path/.acme.sh/acme.sh --installcert -d $domain --key-file $user_path/cert/$domain.key --fullchain-file $user_path/cert/$domain.cer
                                    if [ ! -s "$user_path/cert/$domain.key" ] && [ ! -s "$user_path/cert/$domain.cer" ]; then
                                        rm $user_path/cert/$domain.key &>/dev/null
                                        rm $user_path/cert/$domain.cer &>/dev/null
                                        rm -rf $user_path/.acme.sh/${domain}_ecc &>/dev/null
                                    fi
                                    if [[ -f "$user_path/cert/$domain.key" && -f "$user_path/cert/$domain.cer" ]]; then
                                        echo "证书已生成并保存到 $user_path/cert 目录下."
                                        mv /etc/nginx/nginx_bak.conf /etc/nginx/nginx.conf
                                        break
                                    fi
                                    echo "证书生成失败."
                                    mv /etc/nginx/nginx_bak.conf /etc/nginx/nginx.conf
                                }
                                if systemctl is-active --quiet nginx; then
                                    systemctl stop nginx
                                    write_conf
                                    systemctl restart nginx
                                else
                                    write_conf
                                    systemctl stop nginx
                                fi
                                break
                            else
                                if [[ $domain == "" ]]; then
                                    break
                                fi
                                echo "输入的域名不合法, 请重新输入."
                            fi
                        done
                        waitfor
                        ;;
                    3|33)
                        noloop=0
                        while true; do
                            echo -e "请输入申请证书的域名, 主体名和可选主体名, 以空格格开, (如: do1.com do2.com)"
                            read -e -p "请输入域名: " domain1 domain2
                            if [[ -n "$domain1" && -z "${domain1##*.*}" ]]; then
                                if [[ -z "$domain2" || (-n "$domain2" && -z "${domain2##*.*}") ]]; then
                                    break
                                else
                                    echo "请输入有效的第二个域名."
                                fi
                            else
                                if [[ $domain1 == "" ]]; then
                                    noloop=1
                                    break
                                fi
                                echo "请输入有效的域名."
                            fi
                        done
                        if [[ $noloop != 1 ]]; then
                        while true; do
                            read -e -p "请输入网站根路径 (如: /home/webroot): " webroot
                            if [[ -d "$webroot" ]]; then
                                break
                            else
                                if [[ $webroot == "" ]]; then
                                    noloop=1
                                    break
                                fi
                                echo "路径 $webroot 不存在，请重新输入。"
                            fi
                        done
                        if [[ $noloop != 1 ]]; then
                        if [[ -n "$domain2" ]]; then
                            $user_path/.acme.sh/acme.sh --register-account -m $random@gmail.com
                            $user_path/.acme.sh/acme.sh --issue -d "$domain1" -d "$domain2" -w "$webroot"
                            $user_path/.acme.sh/acme.sh --installcert -d $domain1 --key-file $user_path/cert/$domain1.key --fullchain-file $user_path/cert/$domain1.cer
                            if [ ! -s "$user_path/cert/$domain1.key" ] && [ ! -s "$user_path/cert/$domain1.cer" ]; then
                                rm $user_path/cert/$domain1.key &>/dev/null
                                rm $user_path/cert/$domain1.cer &>/dev/null
                                rm -rf $user_path/.acme.sh/${domain1}_ecc &>/dev/null
                            fi
                            if [[ -f "$user_path/cert/$domain1.key" && -f "$user_path/cert/$domain1.cer" ]]; then
                                echo "证书已生成并保存到 $user_path/cert 目录下."
                                break
                            fi
                            echo "证书生成失败."
                        else
                            $user_path/.acme.sh/acme.sh --register-account -m $random@gmail.com
                            $user_path/.acme.sh/acme.sh --issue -d "$domain1" -w "$webroot"
                            $user_path/.acme.sh/acme.sh --installcert -d $domain1 --key-file $user_path/cert/$domain1.key --fullchain-file $user_path/cert/$domain1.cer
                            if [ ! -s "$user_path/cert/$domain1.key" ] && [ ! -s "$user_path/cert/$domain1.cer" ]; then
                                rm $user_path/cert/$domain1.key &>/dev/null
                                rm $user_path/cert/$domain1.cer &>/dev/null
                                rm -rf $user_path/.acme.sh/${domain1}_ecc &>/dev/null
                            fi
                            if [[ -f "$user_path/cert/$domain1.key" && -f "$user_path/cert/$domain1.cer" ]]; then
                                echo "证书已生成并保存到 $user_path/cert 目录下."
                                break
                            fi
                            echo "证书生成失败."
                        fi
                        fi
                        fi
                        waitfor
                        ;;
                    4|44)
                        while true; do
                            echo -e "请输入申请证书的域名, 输入子域名, 自动添加泛域名"
                            read -e -p "请输入域名: " domain
                            if [[ $domain == *.* ]]; then
                                read -e -p "请输入Cloudflare API Key: " cf_key
                                read -e -p "请输入Cloudflare 邮箱: " cf_email
                                if [ -z "$cf_key" ] || [ -z "$cf_email" ]; then
                                    echo "输入有误，请确保API Key和邮箱都已经输入"
                                    break
                                fi
                                export CF_Key="$cf_key"
                                export CF_Email="$cf_email"
                                wildcard_domain="*.${domain#*.}"
                                $user_path/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                $user_path/.acme.sh/acme.sh --issue -d "$domain" -d "$wildcard_domain" --dns dns_cf \
                                --key-file       $user_path/cert/"$domain.key"  \
                                --fullchain-file $user_path/cert/"$domain.pem"
                                if [ ! -s "$user_path/cert/$domain.key" ] && [ ! -s "$user_path/cert/$domain.pem" ]; then
                                    rm $user_path/cert/$domain.key &>/dev/null
                                    rm $user_path/cert/$domain.pem &>/dev/null
                                    rm -rf $user_path/.acme.sh/${domain}_ecc &>/dev/null
                                fi
                                if [[ -f "$user_path/cert/$domain.key" && -f "$user_path/cert/$domain.pem" ]]; then
                                    echo "证书已生成并保存到 $user_path/cert 目录下."
                                    break
                                fi
                                echo "证书生成失败."
                                break
                            else
                                if [[ $domain == "" ]]; then
                                    break
                                fi
                                echo "输入的域名不合法，请重新输入."
                            fi
                        done
                        waitfor
                        ;;
                    r|R|rr|RR)
                        break
                        ;;
                    x|X|xx|XX)
                        exit 0
                        ;;
                    *)
                        etag=1
                        ;;
                esac
                done
                ;;
            2|22)
                if [[ $($user_path/.acme.sh/acme.sh --list | wc -l) -eq 1 ]]; then
                    echo "未查询到证书."
                else
                    $user_path/.acme.sh/acme.sh --list
                fi
                waitfor
                ;;
            3|33)
                while true; do
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 更新证书${NC}"
                echo -e "${colored_text2}${NC}"
                if [[ $($user_path/.acme.sh/acme.sh --list | wc -l) -eq 1 ]]; then
                    echo "未查询到证书."
                else
                    $user_path/.acme.sh/acme.sh --list
                fi
                echo -e "${colored_text1}${NC}"
                echo -e "1.  更新指定证书"
                echo -e "2.  方法一: 更新全部证书"
                echo -e "3.  方法二: 强制更新全部证书"
                echo -e "${colored_text1}${NC}"
                echo -e "4.  设置定时更新证书"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                remind3p
                read -e -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        read -e -p "请输请输入要更新的证书的域名: " domain
                        if [[ $domain != "" ]]; then
                            $user_path/.acme.sh/acme.sh --renew -d $domain
                            if [[ $? -eq 0 ]]; then
                                echo "证书更新成功."
                            else
                                echo -e "证书更新${MA}失败${NC}."
                            fi
                        fi
                        echo "操作取消."
                        waitfor
                        ;;
                    2|22)
                        if [[ $($user_path/.acme.sh/acme.sh --list | wc -l) -eq 1 ]]; then
                            echo "未查询到证书."
                            waitfor
                        else
                            $user_path/.acme.sh/acme.sh --renew-all
                            echo "更新证书完成."
                            waitfor
                        fi
                        ;;
                    3|33)
                        if [[ $($user_path/.acme.sh/acme.sh --list | wc -l) -eq 1 ]]; then
                            echo "未查询到证书."
                            waitfor
                        else
                            $user_path/.acme.sh/acme.sh --cron --home $user_path/.acme.sh --force
                        echo "强制更新证书完成."
                        waitfor
                        fi
                        ;;
                    4|44)
                        echo -e "${colored_text1}${NC}"
                        echo "当前Cron表中的acme.sh定时任务："
                        crontab -l | grep 'acme.sh'
                        echo -e "${colored_text1}${NC}"
                        echo "请选择操作: "
                        echo "1.  添加新的 ACME 定时任务"
                        echo "2.  删除所有 ACME 定时任务"
                        echo "3.  手动修改 ACME 定时任务"
                        echo -e "${colored_text1}${NC}"
                        remind3p
                        read -e -p "请输入操作编号 (1/2/3/其它退出操作): " choice
                        case "$choice" in
                            1|11)
                                read -e -p "请输入新的定时任务时间表达式 (例如：* * * * * 表示每分钟执行一次): " schedule
                                if [[ $schedule != "" ]]; then
                                    (crontab -l ; echo "$schedule $user_path/.acme.sh/acme.sh --cron --home $user_path/.acme.sh --force > /dev/null") | crontab -
                                    if [[ $? -eq 0 ]]; then
                                        echo "新的 ACME 定时任务已添加."
                                        crontab -l | grep 'acme.sh'
                                    else
                                        echo -e "定时任务添加${MA}失败${NC}."
                                    fi
                                    waitfor
                                else
                                    echo "操作取消."
                                    waitfor
                                fi
                                ;;
                            2|22)
                                crontab -l | grep -v 'acme.sh' | crontab -
                                echo "所有 ACME 定时任务已删除."
                                waitfor
                                ;;
                            3|33)
                                crontab -e
                                waitfor
                                ;;
                            *)
                                echo "操作取消."
                                waitfor
                                ;;
                        esac
                        ;;
                    r|R|rr|RR)
                        break
                        ;;
                    x|X|xx|XX)
                        exit 0
                        ;;
                    *)
                        etag=1
                        ;;
                esac
                done
                ;;
            4|44)
                while true; do
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 删除证书${NC}"
                echo -e "${colored_text2}${NC}"
                if [[ $($user_path/.acme.sh/acme.sh --list | wc -l) -eq 1 ]]; then
                    echo "未查询到证书."
                else
                    $user_path/.acme.sh/acme.sh --list
                fi
                echo -e "${colored_text2}${NC}"
                echo -e "1.  删除指定证书"
                echo -e "2.  删除全部证书"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                remind3p
                read -e -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        read -e -p "请输请输入要删除的证书的域名: " domain
                        if [[ $domain != "" ]]; then
                            $user_path/.acme.sh/acme.sh --remove -d $domain
                            if [[ $? -eq 0 ]]; then
                                echo "证书删除成功."
                            else
                                echo -e "证书删除${MA}失败${NC}."
                            fi
                            waitfor
                        else
                            echo "操作取消."
                            waitfor
                        fi
                        ;;
                    2|22)
                        list_output=$($user_path/.acme.sh/acme.sh --list)
                        readarray -t domain_array <<< "$(echo "$list_output" | sed -n '2,$p' | awk '{print $1}')"
                        echo "${domain_array[@]}"
                        for domain in "${domain_array[@]}"; do
                            $user_path/.acme.sh/acme.sh --remove -d "$domain"
                            echo "已删除域名: $domain"
                        done
                        waitfor
                        ;;
                    r|R|rr|RR)
                        break
                        ;;
                    x|X|xx|XX)
                        exit 0
                        ;;
                    *)
                        etag=1
                        ;;
                esac
                done
                ;;
            i|I|ii|II)
                $pm install -y socat
                curl https://get.acme.sh | sh
                ;;
            d|D|dd|DD)
                $user_path/.acme.sh/acme.sh --uninstall
                rm -rf $user_path/.acme.sh
                ;;
            r|R|rr|RR)
                break
                ;;
            x|X|xx|XX)
                exit 0
                ;;
            *)
                etag=1
                ;;
        esac
        done
        onlyone=0
        ;;
    3|33)
        wget --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
        chmod +x tcpx.sh
        bash tcpx.sh
        rm -f tcpx.sh
        onlyone=0
        ;;
    4|44)
        wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
        bash menu.sh [option] [lisence/url/token]
        rm -f menu.sh
        onlyone=0
        ;;
    o|O|oo|OO)
        echo "调试阶段停用."
        waitfor
        # curl -o redx.sh https://raw.githubusercontent.com/ieiian/Shell/dev/redx.sh && chmod +x redx.sh && ./redx.sh
        onlyone=0
        ;;
    x|X|xx|XX)
        exit 0
        ;;
    *)
        etag=1
        onlyone=0
        ;;
esac
done
