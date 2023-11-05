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

clear_screen(){
    if command -v apt &>/dev/null; then
        clear
    elif command -v yum &>/dev/null; then
        printf "\033c"
    else
        echo
        echo -e "${BK}■ ${RE}■ ${GR}■ ${YE}■ ${BL}■ ${MA}■ ${CY}■ ${WH}■ ${BL}■ ${GR}■ ${BK}■"
    fi
}

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

if ! command -v curl &> /dev/null || ! command -v wget &> /dev/null; then
    $pm install -y curl wget
fi

(EUID=$(id -u)) 2>/dev/null

while true; do
clear_screen

if [ "$EUID" -eq 0 ]; then
    user_path="/root"
else
    user_path="/home/$(whoami)"
    echo -e "${GR}当前用户为非root用户，部分操作可能无法顺利进行。${NC}"
fi

echo -e "${RE}RedX 一键脚本工具 v1.0${NC}"
echo -e " ____  _____ ______  __ "
echo -e "|  _ \| ____|  _ \ \/ / "
echo -e "| |_) |  _| | | | \  /  "
echo -e "|  _ <| |___| |_| /  \  "
echo -e "|_| \_\_____|____/_/\_\ "
echo -e "${BK}■ ${RE}■ ${GR}■ ${YE}■ ${BL}■ ${MA}■ ${CY}■ ${WH}■ ${BL}■ ${GR}■ ${BK}■"
echo -e "${colored_text2}${NC}"
echo -e "1.  V2RAY 节点搭建及相关操作 ▶"
echo -e "2.  ACME  证书申请及相关操作 ▶"
echo -e "3.  BBR   安装及相关操作 ▶"
echo -e "4.  WARP  安装及相关操作 ▶"
echo -e "${colored_text1}${NC}"
echo -e "o.  更新脚本"
echo -e "${colored_text1}${NC}"
echo -e "x.  退出脚本"
echo -e "${colored_text1}${NC}"
read -p "请输入你的选择: " -n 2 -r choice

case $choice in
    1|11)
        while true; do
        if command -v v2ray &> /dev/null; then
            v2ver=$(v2ray version | head -n 1 | awk '{print $1, $2}')
            v2tag=""
        else
            v2ver="未安装"
            v2tag="*"
        fi
        clear_screen
        echo -e "${GR}▼▼${NC}"
        echo -e "${GR}V2RAY${NC}          ${MA}$v2ver${NC}"
        echo -e "${colored_text2}${NC}"
        echo -e "1.  创建节点"
        echo -e "2.  查询节点"
        echo -e "3.  修改节点"
        echo -e "4.  删除节点"
        echo -e "${colored_text1}${NC}"
        echo -e "i.  安装/更新 V2RAY 官方脚本 ${MA}$v2tag${NC}"
        echo -e "u.  更新 .dat 文件"
        echo -e "d.  删除 V2RAY 官方脚本"
        echo -e "${colored_text1}${NC}"
        echo -e "r.  返回主菜单"
        echo -e "${colored_text1}${NC}"
        echo -e "x.  退出脚本"
        echo -e "${colored_text1}${NC}"
        read -p "请输入你的选择: " -n 2 -r choice
        case $choice in
            1|11)
                ;;
            2|22)
                ;;
            3|33)
                ;;
            4|44)
                ;;
            i|ii|I|II)
                echo
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
                sudo sed -i "s/User=.*/User=$(whoami)/" "/etc/systemd/system/v2ray.service"
                sudo systemctl daemon-reload
                ;;
            u|U|uu|UU)
                echo
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-dat-release.sh)
                ;;
            d|D|dd|DD)
                echo
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
                ;;
            r|R|rr|RR)
                echo
                break
                ;;
            x|X|xx|XX)
                echo
                exit 0
                ;;
            *)
                echo "无效的选项，请重新输入。"
                ;;
        esac
        echo -e ${GR}操作完成${NC}
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        done
        ;;
    2|22)
        while true; do
        clear_screen
        echo -e "${GR}▼▼${NC}"
        echo -e "${GR}ACME${NC}"
        echo -e "${colored_text2}${NC}"
        echo -e "1.  安装/更新 ACME 官方脚本"
        echo -e "2.  申请证书"
        echo -e "3.  查询证书"
        echo -e "4.  更新证书"
        echo -e "5.  删除证书"
        echo -e "${colored_text1}${NC}"
        echo -e "r.  返回主菜单"
        echo -e "${colored_text1}${NC}"
        echo -e "x.  退出脚本"
        echo -e "${colored_text1}${NC}"
        read -p "请输入你的选择: " -n 2 -r choice
        case $choice in
            1|11)
                echo
                $pm install -y socat
                curl https://get.acme.sh | sh
                ;;
            2|22)
                while true; do
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 申请证书${NC}"
                echo -e "${colored_text2}${NC}"
                echo -e "1.  方法一: 采用端口 80 验证方式申请"
                echo -e "2.  方法二: 采用 Nginx 验证方式申请 (需要安装Nginx)"
                echo -e "3.  方法三: 采用 http 绝对路径方式验证申请"
                echo -e "4.  方法四: 采用 cloudflare 的 DNS 验证方式申请"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "${colored_text1}${NC}"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                read -p "请输入你的选择: " -n 2 -r choice
                case $choice in
                    1|11)
                        ;;
                    2|22)
                        ;;
                    3|33)
                        ;;
                    4|44)
                        ;;
                    r|R|rr|RR)
                        echo
                        break
                        ;;
                    x|X|xx|XX)
                        echo
                        exit 0
                        ;;
                    *)
                        echo "无效的选项，请重新输入。"
                        ;;
                    esac
                    echo -e ${GR}操作完成${NC}
                    echo "按任意键继续..."
                    read -n 1 -s -r -p ""
                    done
                ;;
            3|33)
                ~/.acme.sh/acme.sh --list
                ;;
            4|44)
                while true; do
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 更新证书${NC}"
                echo -e "${colored_text2}${NC}"
                echo -e "1.  方法一: 更新全部证书"
                echo -e "2.  方法二: 强制更新全部证书"
                echo -e "${colored_text1}${NC}"
                echo -e "3.  方法三: 更新指定证书"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "${colored_text1}${NC}"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                read -p "请输入你的选择: " -n 2 -r choice
                case $choice in
                    1|11)
                        ;;
                    2|22)
                        ;;
                    3|33)
                        ;;
                    r|R|rr|RR)
                        echo
                        break
                        ;;
                    x|X|xx|XX)
                        echo
                        exit 0
                        ;;
                    *)
                        echo "无效的选项，请重新输入。"
                        ;;
                    esac
                    echo -e ${GR}操作完成${NC}
                    echo "按任意键继续..."
                    read -n 1 -s -r -p ""
                    done
                ;;
            5|55)
                ;;
            r|R|rr|RR)
                echo
                break
                ;;
            x|X|xx|XX)
                echo
                exit 0
                ;;
            *)
                echo "无效的选项，请重新输入。"
                ;;
        esac
        echo -e ${GR}操作完成${NC}
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        done
        ;;
    3|33)
        ;;
    4|44)
        ;;
    o|O|oo|OO)
        curl -o redx.sh https://raw.githubusercontent.com/ieiian/Shell/dev/redx.sh && chmod +x redx.sh && ./redx.sh
        ;;
    x|X|xx|XX)
        echo
        exit
        ;;
    *)
        echo
        echo "无效的选项，请重新输入。"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        ;;
esac
done
