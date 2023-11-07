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
remind() {
    if [ "$etag" == 1 ]; then
        echo -e "${MA}无效的选项, 请重新输入.${NC}"
        etag=0
    else
        echo -e "${GR}● ● ● ${NC}"
    fi
}
waitfor() {
    echo -e ${GR}操作完成${NC}
    echo "按任意键继续..."
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
if ! command -v curl &>/dev/null || ! command -v wget &>/dev/null || ! command -v ifconfig &>/dev/null; then
    clear_screen
    echo -e "${GR}▼${NC}"
    echo -e "${colored_text2}${NC}"
    echo -e "CURL/WGET/NET-TOOLS"
    read -p "检查到部分依赖工具没有安装, 是否要进行安装? (Y/其它跳过): " -n 3 -r choice
    if [[ $choice == "Y" || $choice == "y" ]]; then
        $pm install -y curl wget net-tools
    fi
fi
(EUID=$(id -u)) 2>/dev/null
virt_check
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
echo -e "x.  退出脚本"
echo -e "${colored_text1}${NC}"
remind
read -p "请输入你的选择: " -n 2 -r choice && echoo
case $choice in
    1|11)
        while true; do
        if command -v v2ray &>/dev/null; then
            v2ver=$(v2ray version | head -n 1 | awk '{print $1, $2}')
            v2tag=""
        else
            v2ver="未安装"
            v2tag="*"
        fi
        node=()
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
        echo -e "x.  退出脚本"
        echo -e "${colored_text1}${NC}"
        remind
        read -p "请输入你的选择: " -n 2 -r choice && echoo
        case $choice in
            1|11)
                nodetitle() {
                    clear_screen
                    echo -e "${GR}▼▼▼${NC}"
                    echo -e "${GR}节点信息${NC}"
                    echo -e "${colored_text2}${NC}"
                    for ((i=1; i<=${#node[@]}; i++)); do
                        echo "节点 $i 类型: ${node[$i]}"
                    done
                    echo -e "${colored_text1}${NC}"
                    remind
                }
                while true; do
                nodetitle
                echo "节点类型: 1.Vmess  2.Vless"
                read -p "请先择创建节点类型 (1/2/C取消): " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        node[1]="Vmess"
                        ;;
                    2|22)
                        node[1]="Vless"
                        ;;
                    c|cc|C|CC)
                        break
                        ;;
                    *)
                        etag=1
                        ;;

                esac
                done
                while true; do
                nodetitle
                echo "节点类型: 1.Vmess  2.Vless"
                read -p "请先择创建节点类型 (1/2/C取消): " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        node[2]="Vmess"
                        ;;
                    2|22)
                        node[2]="Vless"
                        ;;
                    c|cc|C|CC)
                        break
                        ;;
                    *)
                        etag=1
                        ;;

                esac
                done
                ;;
            2|22)
                ;;
            3|33)
                ;;
            4|44)
                ;;
            i|ii|I|II)
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
                sudo sed -i "s/User=.*/User=$(whoami)/" "/etc/systemd/system/v2ray.service"
                sudo systemctl daemon-reload
                ;;
            u|U|uu|UU)
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-dat-release.sh)
                ;;
            d|D|dd|DD)
                bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
                read -p "是否要删除所有残留(包括配置文件)? (Y/其它跳过): " choice
                if [[ $choice == "Y" || $choice == "y" ]]; then
                    rm -rf /usr/local/etc/v2ray
                    rm -rf /var/log/v2ray
                fi
                ### 以下两行为删除/tmp下所有带v2ray关健定的文件或文件夹 (额外添加, 可以去除)
                # find /tmp -type f -name "*v2ray*" -exec rm -f {} +
                # find /tmp -type d -name "*v2ray*" -exec rm -rf {} +
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
        while true; do
        if [ -x "/root/.acme.sh/acme.sh" ]; then
            acmever=$(~/.acme.sh/acme.sh --version | sed -n '2p' | awk '{print $1}')
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
        remind
        read -p "请输入你的选择: " -n 2 -r choice && echoo
        case $choice in
            1|11)
                if [ ! -d ~/cert ]; then
                    mkdir ~/cert
                fi
                while true; do
                random=$((RANDOM % 1000000))
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
                remind
                read -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        while true; do
                            read -p "请输入申请证书的域名: " domain
                            if [[ $domain == *.* ]]; then
                                pids=$(lsof -t -i :80)
                                if [ -n "$pids" ]; then
                                    for pid in $pids; do
                                        kill -9 $pid &>/dev/null
                                    done
                                fi
                                ~/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                ~/.acme.sh/acme.sh --issue -d $domain --standalone
                                ~/.acme.sh/acme.sh --installcert -d $domain --key-file ~/cert/$domain.key --fullchain-file ~/cert/$domain.cer
                                if [ ! -s "~/cert/$domain.key" ] && [ ! -s "~/cert/$domain.cer" ]; then
                                    rm ~/cert/$domain.key &>/dev/null
                                    rm ~/cert/$domain.cer &>/dev/null
                                    rm -rf ~/.acme.sh/${domain}_ecc &>/dev/null
                                fi
                                if [[ -f "~/cert/$domain.key" && -f "~/cert/$domain.cer" ]]; then
                                    echo "证书已生成并保存到 ~/cert 目录下."
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
                            read -p "请输入申请证书的域名: " domain
                            if [[ $domain == *.* ]]; then
                                pids=$(lsof -t -i :80)
                                if [ -n "$pids" ]; then
                                    for pid in $pids; do
                                        kill -9 $pid
                                    done
                                fi
                                if ! command -v nginx &>/dev/null; then
                                    read -p "系统未检测到Nginx, 是否进行Nginx安装 (Y/其它跳过): " choice
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
                                    ~/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                    ~/.acme.sh/acme.sh --issue -d $domain --nginx
                                    ~/.acme.sh/acme.sh --installcert -d $domain --key-file ~/cert/$domain.key --fullchain-file ~/cert/$domain.cer
                                    if [ ! -s "~/cert/$domain.key" ] && [ ! -s "~/cert/$domain.cer" ]; then
                                        rm ~/cert/$domain.key &>/dev/null
                                        rm ~/cert/$domain.cer &>/dev/null
                                        rm -rf ~/.acme.sh/${domain}_ecc &>/dev/null
                                    fi
                                    if [[ -f "~/cert/$domain.key" && -f "~/cert/$domain.cer" ]]; then
                                        echo "证书已生成并保存到 ~/cert 目录下."
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
                            read -p "请输入域名: " domain1 domain2
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
                            read -p "请输入网站根路径 (如: /home/webroot): " webroot
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
                            ~/.acme.sh/acme.sh --register-account -m $random@gmail.com
                            ~/.acme.sh/acme.sh --issue -d "$domain1" -d "$domain2" -w "$webroot"
                            ~/.acme.sh/acme.sh --installcert -d $domain1 --key-file ~/cert/$domain1.key --fullchain-file ~/cert/$domain1.cer
                            if [ ! -s "~/cert/$domain1.key" ] && [ ! -s "~/cert/$domain1.cer" ]; then
                                rm ~/cert/$domain1.key &>/dev/null
                                rm ~/cert/$domain1.cer &>/dev/null
                                rm -rf ~/.acme.sh/${domain1}_ecc &>/dev/null
                            fi
                            if [[ -f "~/cert/$domain1.key" && -f "~/cert/$domain1.cer" ]]; then
                                echo "证书已生成并保存到 ~/cert 目录下."
                                break
                            fi
                            echo "证书生成失败."
                        else
                            ~/.acme.sh/acme.sh --register-account -m $random@gmail.com
                            ~/.acme.sh/acme.sh --issue -d "$domain1" -w "$webroot"
                            ~/.acme.sh/acme.sh --installcert -d $domain1 --key-file ~/cert/$domain1.key --fullchain-file ~/cert/$domain1.cer
                            if [ ! -s "~/cert/$domain1.key" ] && [ ! -s "~/cert/$domain1.cer" ]; then
                                rm ~/cert/$domain1.key &>/dev/null
                                rm ~/cert/$domain1.cer &>/dev/null
                                rm -rf ~/.acme.sh/${domain1}_ecc &>/dev/null
                            fi
                            if [[ -f "~/cert/$domain1.key" && -f "~/cert/$domain1.cer" ]]; then
                                echo "证书已生成并保存到 ~/cert 目录下."
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
                            read -p "请输入域名: " domain
                            if [[ $domain == *.* ]]; then
                                read -p "请输入Cloudflare API Key: " cf_key
                                read -p "请输入Cloudflare 邮箱: " cf_email
                                if [ -z "$cf_key" ] || [ -z "$cf_email" ]; then
                                    echo "输入有误，请确保API Key和邮箱都已经输入"
                                    break
                                fi
                                export CF_Key="$cf_key"
                                export CF_Email="$cf_email"
                                wildcard_domain="*.${domain#*.}"
                                ~/.acme.sh/acme.sh --register-account -m $random@gmail.com
                                ~/.acme.sh/acme.sh --issue -d "$domain" -d "$wildcard_domain" --dns dns_cf \
                                --key-file       ~/cert/"$domain.key"  \
                                --fullchain-file ~/cert/"$domain.pem"
                                if [ ! -s "~/cert/$domain.key" ] && [ ! -s "~/cert/$domain.pem" ]; then
                                    rm ~/cert/$domain.key &>/dev/null
                                    rm ~/cert/$domain.pem &>/dev/null
                                    rm -rf ~/.acme.sh/${domain}_ecc &>/dev/null
                                fi
                                if [[ -f "~/cert/$domain.key" && -f "~/cert/$domain.pem" ]]; then
                                    echo "证书已生成并保存到 ~/cert 目录下."
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
                ~/.acme.sh/acme.sh --list
                waitfor
                ;;
            3|33)
                while true; do
                clear_screen
                echo -e "${GR}▼▼▼${NC}"
                echo -e "${GR}ACME - 更新证书${NC}"
                echo -e "${colored_text2}${NC}"
                ~/.acme.sh/acme.sh --list
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
                remind
                read -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        read -p "请输请输入要删除的证书的域名: " domain
                        ~/.acme.sh/acme.sh --renew -d $domain
                        if [[ $? -eq 0 ]]; then
                            echo "证书更新成功."
                        else
                            echo -e "证书更新${MA}失败${NC}."
                        fi
                        waitfor
                        ;;
                    2|22)
                        ~/.acme.sh/acme.sh --renew-all
                        echo "更新证书完成."
                        waitfor
                        ;;
                    3|33)
                        ~/.acme.sh/acme.sh --cron --home /root/.acme.sh --force
                        echo "更新证书完成."
                        waitfor
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
                        remind
                        read -p "请输入操作编号 (1/2/3/其它退出操作): " choice
                        case "$choice" in
                            1|11)
                                read -p "请输入新的定时任务时间表达式 (例如：* * * * * 表示每分钟执行一次): " schedule
                                (crontab -l ; echo "$schedule /root/.acme.sh/acme.sh --cron --home /root/.acme.sh --force > /dev/null") | crontab -
                                crontab -l | grep 'acme.sh'
                                echo "新的 ACME 定时任务已添加."
                                waitfor
                                ;;
                            2|22)
                                crontab -l | grep -v 'acme.sh' | crontab -
                                echo "所有 ACME 定时任务已删除."
                                waitfor
                                ;;
                            3|33)
                                crontab -e
                                ;;
                            *)
                                etag=1
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
                ~/.acme.sh/acme.sh --list
                echo -e "${colored_text2}${NC}"
                echo -e "1.  删除指定证书"
                echo -e "2.  删除全部证书"
                echo -e "${colored_text1}${NC}"
                echo -e "r.  返回上层菜单"
                echo -e "x.  退出脚本"
                echo -e "${colored_text1}${NC}"
                remind
                read -p "请输入你的选择: " -n 2 -r choice && echoo
                case $choice in
                    1|11)
                        read -p "请输请输入要删除的证书的域名: " domain
                        ~/.acme.sh/acme.sh --remove -d $domain
                        if [[ $? -eq 0 ]]; then
                            echo "证书删除成功."
                        else
                            echo -e "证书删除${MA}失败${NC}."
                        fi
                        waitfor
                        ;;
                    2|22)
                        list_output=$(~/.acme.sh/acme.sh --list)
                        readarray -t domain_array <<< "$(echo "$list_output" | sed -n '2,$p' | awk '{print $1}')"
                        echo "${domain_array[@]}"
                        for domain in "${domain_array[@]}"; do
                            ~/.acme.sh/acme.sh --remove -d "$domain"
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
                ~/.acme.sh/acme.sh --uninstall
                rm -rf ~/.acme.sh
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
    3|33)
        wget --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
        chmod +x tcpx.sh
        bash tcpx.sh
        ;;
    4|44)
        wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh
        bash menu.sh [option] [lisence/url/token]
        ;;
    o|O|oo|OO)
        curl -o redx.sh https://raw.githubusercontent.com/ieiian/Shell/dev/redx.sh && chmod +x redx.sh && ./redx.sh
        ;;
    x|X|xx|XX)
        exit
        ;;
    *)
        etag=1
        ;;
esac
done
