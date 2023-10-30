while true; do
export LANG="en_US.UTF-8"
clear

echo -e "\033[35m _____ \033[36m ____  \033[33m _____ "
echo -e "\033[35m|_   _|\033[36m/ ___| \033[33m| ____|"
echo -e "\033[35m  | |  \033[36m\___ \ \033[33m|  _|  "
echo -e "\033[35m  | |  \033[36m ___) |\033[33m| |___ "
echo -e "\033[35m  |_|  \033[36m|____/ \033[33m|_____|"
echo -e "\033[32m====================="
echo -e "\033[96mTSE 一键脚本工具 v1.0.1 （支持Ubuntu，Debian，Centos系统）\033[0m"
echo "------------------------"
echo "1.  系统信息"
echo "2.  系统更新"
echo "3.  系统设置 ▶"
echo "4.  常用工具安装 ▶"
echo "5.  网络优化安装 ▶"
echo "6.  测试脚本合集 ▶"
echo "7.  Docker管理 ▶"
echo "8.  工作区 ▶▶▶ "
echo "------------------------"
echo "9.  其它设置"
echo "------------------------"
echo "10. 更新脚本"
echo "------------------------"
echo "0.  退出脚本"
echo "------------------------"
read -p "请输入你的选择: " choice

case $choice in
    1)
        clear
        echo "请稍后..."
        # 函数: 获取IPv4和IPv6地址
        fetch_ip_addresses() {
        ipv4_address_cn=$(curl -s cip.cc | grep -oE 'IP\s+:\s+\S+' | awk '{print $3}')
        ipv4_address=$(curl -s ipv4.ip.gs)
        # ipv6_address=$(curl -s ipv6.ip.sb)
        ipv6_address=$(curl -s --max-time 2 ipv6.ip.gs)
        }

        # 获取IP地址
        fetch_ip_addresses > /dev/null 2>&1

        if [ "$(uname -m)" == "x86_64" ]; then
        cpu_info=$(cat /proc/cpuinfo | grep 'model name' | uniq | sed -e 's/model name[[:space:]]*: //')
        else
        cpu_info=$(lscpu | grep 'Model name' | sed -e 's/Model name[[:space:]]*: //')
        fi

        cpu_usage=$(top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}')
        cpu_usage_percent=$(printf "%.2f" "$cpu_usage")%

        cpu_cores=$(nproc)

        mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

        disk_info=$(df -h | awk '$NF=="/"{printf "%d/%dGB (%s)", $3,$2,$5}')
        country_cn=$(curl -s ipinfo.io/$ipv4_address_cn/country)
        city_cn=$(curl -s ipinfo.io/$ipv4_address_cn/city)
        country=$(curl -s ipinfo.io/$ipv4_address/country)
        city=$(curl -s ipinfo.io/$ipv4_address/city)

        isp_info=$(curl -s ipinfo.io/org)

        cpu_arch=$(uname -m)

        hostname=$(hostname)

        kernel_version=$(uname -r)

        local_ipv4=$(ip -4 addr show | awk '/inet / {split($2, a, "/"); if (a[1] ~ /^192\.|^10\./) print a[1]}')

        congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
        queue_algorithm=$(sysctl -n net.core.default_qdisc)

        # 尝试使用 lsb_release 获取系统信息
        os_info=$(lsb_release -ds 2>/dev/null)

        # 如果 lsb_release 命令失败，则尝试其他方法
        if [ -z "$os_info" ]; then
        # 检查常见的发行文件
        if [ -f "/etc/os-release" ]; then
            os_info=$(source /etc/os-release && echo "$PRETTY_NAME")
        elif [ -f "/etc/debian_version" ]; then
            os_info="Debian $(cat /etc/debian_version)"
        elif [ -f "/etc/redhat-release" ]; then
            os_info=$(cat /etc/redhat-release)
        else
            os_info="Unknown"
        fi
        fi

        clear
        output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
            NR > 2 { rx_total += $2; tx_total += $10 }
            END {
                rx_units = "Bytes";
                tx_units = "Bytes";
                if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
                if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
                if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

                if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
                if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
                if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

                printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
            }' /proc/net/dev)


        current_time=$(date "+%Y-%m-%d %I:%M %p")

        swap_used=$(free -m | awk 'NR==3{print $3}')
        swap_total=$(free -m | awk 'NR==3{print $2}')

        if [ "$swap_total" -eq 0 ]; then
            swap_percentage=0
        else
            swap_percentage=$((swap_used * 100 / swap_total))
        fi

        swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

        echo " ▼ "
        echo "系统信息查询"
        echo "------------------------"
        echo "主机名: $hostname"
        echo "运营商: $isp_info"
        echo "------------------------"
        echo "系统版本: $os_info"
        echo "Linux版本: $kernel_version"
        echo "------------------------"
        echo "CPU架构: $cpu_arch"
        echo "CPU型号: $cpu_info"
        echo "CPU核心: $cpu_cores   CPU占用: $cpu_usage_percent"
        echo "------------------------"
        echo "物理内存: $mem_info"
        echo "虚拟内存: $swap_info"
        echo "硬盘占用: $disk_info"
        echo "------------------------"
        echo "$output"
        echo "------------------------"
        echo "网络拥堵算法: $congestion_algorithm $queue_algorithm"
        echo "------------------------"
        if [[ -z "$local_ipv4" || "$local_ipv4" == *"error code"* ]]; then
            echo "本地IPv4地址(局): 获取失败，请使用指令:"ip a"查询！"
        else
            echo "本地IPv4地址(局): $local_ipv4"
        fi
        # echo "本地IPv4地址(局): $local_ipv4"
        if [[ -z "$ipv4_address_cn" || "$ipv4_address_cn" == *"error code"* ]]; then
            # echo "公网IPv4地址(内): 远程获取失败"
            :
        else
            echo "公网IPv4地址(内): $ipv4_address_cn"
        fi
        # echo "公网IPv4地址(内): $ipv4_address_cn"
        if [[ -z "$ipv4_address" || "$ipv4_address" == *"error code"* ]]; then
            # echo "公网IPv4地址(外): 远程获取失败"
            :
        else
            echo "公网IPv4地址(外): $ipv4_address"
        fi
        # echo "公网IPv4地址(外): $ipv4_address"
        if [[ -z "$ipv6_address" || "$ipv6_address" == *"error code"* ]]; then
            # echo "公网IPv6地址: 远程获取失败"
            :
        else
            echo "公网IPv6地址: $ipv6_address"
        fi
        # echo "公网IPv6地址: $ipv6_address"
        echo "------------------------"
        if [[ -z "$ipv4_address_cn" || "$ipv4_address_cn" == *"error code"* ]]; then
            :
        else
            echo "地理位置(内): $country_cn $city_cn"
        fi
        # echo "地理位置(内): $country_cn $city_cn"
        if [[ -z "$ipv4_address" || "$ipv4_address" == *"error code"* ]]; then
            :
        else
            echo "地理位置(外): $country $city"
        fi
        # echo "地理位置(外): $country $city"
        echo "系统时间: $current_time"
        echo
        ;;

    2)
        while true; do
            read -p "是否要进行完全升级(-upgrade)？(Y/N，或C取消，回车默认为N): " choice
            case "$choice" in
                [Yy])
                    # 更新并升级
                    clear
                    echo " ▼ "
                    echo "系统更新中..."
                    # Update system on Debian-based systems
                    if [ -f "/etc/debian_version" ]; then
                        DEBIAN_FRONTEND=noninteractive apt update -y && DEBIAN_FRONTEND=noninteractive apt full-upgrade -y
                    fi
                    # Update system on Red Hat-based systems
                    if [ -f "/etc/redhat-release" ]; then
                        yum -y update && yum -y upgrade
                    fi
                    break  # 退出循环
                    ;;
                [Nn]|"")
                    clear
                    echo " ▼ "
                    echo "系统更新中..."
                    # Update system on Debian-based systems
                    if [ -f "/etc/debian_version" ]; then
                        DEBIAN_FRONTEND=noninteractive apt update -y
                    fi
                    # Update system on Red Hat-based systems
                    if [ -f "/etc/redhat-release" ]; then
                        yum -y update
                    fi
                    break  # 退出循环
                    ;;
                [Cc])
                    # 取消操作
                    echo "操作已取消。"
                    sleep 2  # 等待2秒
                    break  # 退出循环
                    ;;
                *)
                    # 无效输入
                    if [ -n "$choice" ]; then
                        echo "无效的输入，请选择 Y、N、C 或直接按回车。"
                    fi
                    ;;
            esac
        done
        ;;

    3)
        clear
        while true; do

        echo " ▼ "
        echo "系统设置"
        echo "------------------------"
        echo "1.  设置脚本快捷键"
        echo "------------------------"
        echo "2.  修改ROOT密码"
        echo "3.  开启ROOT密码登录模式"
        echo "4.  禁用ROOT账户创建新账户"
        echo "5.  用户管理"
        echo "6.  用户/密码/UUID生成器"
        echo "------------------------"
        echo "7.  修改SSH连接端口"
        echo "8.  查询端口占用状态"
        echo "9.  开放所有端口"
        echo "------------------------"
        echo "10. 优化DNS地址"
        echo "11. 切换优先ipv4/ipv6"
        echo "12. 修改虚拟内存大小"
        echo "------------------------"
        echo "13. 安装Python最新版"
        echo "------------------------"
        echo "14. 系统清理"
        echo "15. 重装系统"
        echo "------------------------"
        echo "0.  返回主菜单"
        echo "00. 退出脚本"
        echo "------------------------"
        read -p "请输入你的选择: " sub_choice

        case $sub_choice in
            1)
                clear
                while true; do
                    read -p "请输入你的快捷按键: " kjj
                    if [ -z "$kjj" ]; then
                        echo "错误：快捷按键不能为空，请重新输入。"
                    else
                        echo "alias $kjj='cd ~ && curl -sS -O https://raw.githubusercontent.com/ieiian/shell/main/tse.sh && chmod +x tse.sh && ./tse.sh'" >> ~/.bashrc
                        echo "快捷键已添加。请重新启动终端，或运行 'source ~/.bashrc' 以使修改生效。"
                        break
                    fi
                done
                ;;
            2)
                clear
                echo "设置你的ROOT密码"
                passwd
                ;;
            3)
                clear
                echo "设置你的ROOT密码"
                passwd
                sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
                sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
                service sshd restart
                echo "ROOT登录设置完毕！"
                read -p "需要重启服务器吗？(Y/N): " choice
                case "$choice" in
                [Yy])
                reboot
                ;;
                [Nn])
                echo "已取消"
                ;;
                *)
                echo "无效的选择，请输入 Y 或 N。"
                ;;
                esac
                ;;
            4)
                clear
                if ! command -v sudo &>/dev/null; then
                    if command -v apt &>/dev/null; then
                        apt update -y && apt install -y sudo
                    elif command -v yum &>/dev/null; then
                        yum -y update && yum -y install sudo
                    else
                        exit 1
                    fi
                fi

                # 提示用户输入新用户名
                read -p "请输入新用户名: " new_username

                # 创建新用户并设置密码
                sudo useradd -m -s /bin/bash "$new_username"
                sudo passwd "$new_username"

                # 赋予新用户sudo权限
                echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

                # 禁用ROOT用户登录
                sudo passwd -l root

                echo "操作已完成。"
                ;;

            5)
                while true; do
                    clear
                    # 显示所有用户、用户权限、用户组和是否在sudoers中
                    echo "用户列表"
                    echo "----------------------------------------------------------------------------"
                    printf "%-24s %-34s %-20s %-10s\n" "用户名" "用户权限" "用户组" "sudo权限"
                    while IFS=: read -r username _ userid groupid _ _ homedir shell; do
                        groups=$(groups "$username" | cut -d : -f 2)
                        sudo_status=$(sudo -n -lU "$username" 2>/dev/null | grep -q '(ALL : ALL)' && echo "Yes" || echo "No")
                        printf "%-20s %-30s %-20s %-10s\n" "$username" "$homedir" "$groups" "$sudo_status"
                    done < /etc/passwd

                    echo " ▼ "
                    echo "系统设置 - 账户管理"
                    echo ""
                    echo ""
                    echo "1. 创建普通账户             2. 创建高级账户"
                    echo "------------------------"
                    echo "3. 赋予最高权限             4. 取消最高权限"
                    echo "------------------------"
                    echo "5. 删除账号"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                        if ! command -v sudo &>/dev/null; then
                            if command -v apt &>/dev/null; then
                                apt update -y && apt install -y sudo
                            elif command -v yum &>/dev/null; then
                                yum -y update && yum -y install sudo
                            else
                                echo ""
                            fi
                        fi

                        # 提示用户输入新用户名
                        read -p "请输入新用户名: " new_username

                        # 创建新用户并设置密码
                        sudo useradd -m -s /bin/bash "$new_username"
                        sudo passwd "$new_username"

                        echo "操作已完成。"
                            ;;

                        2)
                        if ! command -v sudo &>/dev/null; then
                            if command -v apt &>/dev/null; then
                                apt update -y && apt install -y sudo
                            elif command -v yum &>/dev/null; then
                                yum -y update && yum -y install sudo
                            else
                                echo ""
                            fi
                        fi

                        # 提示用户输入新用户名
                        read -p "请输入新用户名: " new_username

                        # 创建新用户并设置密码
                        sudo useradd -m -s /bin/bash "$new_username"
                        sudo passwd "$new_username"

                        # 赋予新用户sudo权限
                        echo "$new_username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers

                        echo "操作已完成。"

                            ;;
                        3)
                        if ! command -v sudo &>/dev/null; then
                            if command -v apt &>/dev/null; then
                                apt update -y && apt install -y sudo
                            elif command -v yum &>/dev/null; then
                                yum -y update && yum -y install sudo
                            else
                                echo ""
                            fi
                        fi

                        read -p "请输入用户名: " username
                        # 赋予新用户sudo权限
                        echo "$username ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers
                            ;;
                        4)
                        if ! command -v sudo &>/dev/null; then
                            if command -v apt &>/dev/null; then
                                apt update -y && apt install -y sudo
                            elif command -v yum &>/dev/null; then
                                yum -y update && yum -y install sudo
                            else
                                echo ""
                            fi
                        fi
                        read -p "请输入用户名: " username
                        # 从sudoers文件中移除用户的sudo权限
                        sudo sed -i "/^$username\sALL=(ALL:ALL)\sALL/d" /etc/sudoers

                            ;;
                        5)
                        if ! command -v sudo &>/dev/null; then
                            if command -v apt &>/dev/null; then
                                apt update -y && apt install -y sudo
                            elif command -v yum &>/dev/null; then
                                yum -y update && yum -y install sudo
                            else
                                echo ""
                            fi
                        fi
                        read -p "请输入要删除的用户名: " username
                        # 删除用户及其主目录
                        sudo userdel -r "$username"

                            ;;

                        0)
                            break  # 跳出循环，退出菜单
                            ;;

                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
                done
                ;;

            6)
                clear

                echo "随机用户名"
                echo "------------------------"
                for i in {1..5}; do
                    username="user$(< /dev/urandom tr -dc _a-z0-9 | head -c6)"
                    echo "随机用户名 $i: $username"
                done

                echo ""
                echo "随机姓名"
                echo "------------------------"
                first_names=("Gou" "Zhu" "Ji" "Ma" "Xiaoming" "Meimei" "Gege" "Budao" "Tian" "Feng" "Qiang" "Cong" "Qiu" "Ying" "Xia")
                last_names=("SUN" "ZHANG" "LI" "XIE" "XIAO" "GUANG" "FENG" "GO" "HUANG" "DA" "CAO" "LAN" "LIU" "LIAO")

                # 生成5个随机用户姓名
                for i in {1..5}; do
                    first_name_index=$((RANDOM % ${#first_names[@]}))
                    last_name_index=$((RANDOM % ${#last_names[@]}))
                    user_name="${first_names[$first_name_index]} ${last_names[$last_name_index]}"
                    echo "随机用户姓名 $i: $user_name"
                done

                    echo ""
                    echo "随机UUID"
                    echo "------------------------"
                for i in {1..5}; do
                    uuid=$(cat /proc/sys/kernel/random/uuid)
                    echo "随机UUID $i: $uuid"
                done

                    echo ""
                    echo "16位随机密码"
                    echo "------------------------"
                for i in {1..5}; do
                    password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16)
                    echo "随机密码 $i: $password"
                done

                    echo ""
                    echo "32位随机密码"
                    echo "------------------------"
                for i in {1..5}; do
                    password=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c32)
                    echo "随机密码 $i: $password"
                done
                    echo ""
                ;;
            
            7)
                # 清屏
                clear

                # 获取当前的 SSH 端口号
                current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

                # 打印当前的 SSH 端口号
                echo "当前的 SSH 端口号是: $current_port"

                echo "------------------------"

                # 提示用户输入新的 SSH 端口号
                read -p "请输入新的 SSH 端口号: " new_port

                # 验证输入是否为数字
                if [[ ! "$new_port" =~ ^[0-9]+$ ]]; then
                    echo "错误：请输入有效的端口号。"
                else
                    # 备份 SSH 配置文件
                    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

                    # 替换 SSH 配置文件中的端口号
                    sed -i "s/^ *Port [0-9]\+/Port $new_port/" /etc/ssh/sshd_config

                    # 重启 SSH 服务
                    service ssh restart

                    echo "SSH 端口已修改为: $new_port"
                fi
                ;;
            8)
                clear
                echo " ▼ "
                echo "系统设置 - 查询端口占用状态"
                ss -untlp
                ;;
            9)
                clear
                echo " ▼ "
                echo "系统设置 - 开放所有端口"
                    if ! command -v iptables &> /dev/null; then
                    echo ""
                    else
                        # iptables命令
                        iptables -P INPUT ACCEPT
                        iptables -P FORWARD ACCEPT
                        iptables -P OUTPUT ACCEPT
                        iptables -F
                    fi
                echo "端口已全部开放"
                ;;

            10)
                clear
                echo " ▼ "
                echo "系统设置 - 优化DNS地址"
                echo ""
                echo "------------------------"
                echo "当前DNS地址"
                cat /etc/resolv.conf
                echo "------------------------"
                echo ""
                # 询问用户是否要优化DNS设置
                read -p "是否要设置为Cloudflare和Google的DNS地址？(y/n): " choice

                if [ "$choice" == "y" ]; then
                    # 定义DNS地址
                    cloudflare_ipv4="1.1.1.1"
                    google_ipv4="8.8.8.8"
                    cloudflare_ipv6="2606:4700:4700::1111"
                    google_ipv6="2001:4860:4860::8888"

                    # 检查机器是否有IPv6地址
                    ipv6_available=0
                    if [[ $(ip -6 addr | grep -c "inet6") -gt 0 ]]; then
                        ipv6_available=1
                    fi

                    # 设置DNS地址为Cloudflare和Google（IPv4和IPv6）
                    echo "设置DNS为Cloudflare和Google"

                    # 设置IPv4地址
                    echo "nameserver $cloudflare_ipv4" > /etc/resolv.conf
                    echo "nameserver $google_ipv4" >> /etc/resolv.conf

                    # 如果有IPv6地址，则设置IPv6地址
                    if [[ $ipv6_available -eq 1 ]]; then
                        echo "nameserver $cloudflare_ipv6" >> /etc/resolv.conf
                        echo "nameserver $google_ipv6" >> /etc/resolv.conf
                    fi

                    echo "DNS地址已更新"
                    echo "------------------------"
                    cat /etc/resolv.conf
                    echo "------------------------"
                else
                    echo "DNS设置未更改"
                fi

                ;;          

            11)
                clear
                ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)

                echo ""
                if [ "$ipv6_disabled" -eq 1 ]; then
                    echo "当前网络优先级设置: IPv4 优先"
                else
                    echo "当前网络优先级设置: IPv6 优先"
                fi
                echo "------------------------"

                echo ""
                echo "切换的网络优先级"
                echo "------------------------"
                echo "1. IPv4 优先          2. IPv6 优先"
                echo "------------------------"
                read -p "选择优先的网络: " choice

                case $choice in
                    1)
                        sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
                        echo "已切换为 IPv4 优先"
                        ;;
                    2)
                        sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null 2>&1
                        echo "已切换为 IPv6 优先"
                        ;;
                    *)
                        echo "无效的选择"
                        ;;

                esac
                ;;

            12)

                if [ "$EUID" -ne 0 ]; then
                echo "请以 root 权限运行此脚本。"
                exit 1
                fi

                clear
                # 获取当前交换空间信息
                swap_used=$(free -m | awk 'NR==3{print $3}')
                swap_total=$(free -m | awk 'NR==3{print $2}')

                if [ "$swap_total" -eq 0 ]; then
                swap_percentage=0
                else
                swap_percentage=$((swap_used * 100 / swap_total))
                fi

                swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"

                echo "当前虚拟内存: $swap_info"

                read -p "是否调整大小?(Y/N): " choice

                case "$choice" in
                [Yy])
                    # 输入新的虚拟内存大小
                    read -p "请输入虚拟内存大小MB: " new_swap

                    # 获取当前系统中所有的 swap 分区
                    swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

                    # 遍历并删除所有的 swap 分区
                    for partition in $swap_partitions; do
                    swapoff "$partition"
                    wipefs -a "$partition"  # 清除文件系统标识符
                    mkswap -f "$partition"
                    echo "已删除并重新创建 swap 分区: $partition"
                    done

                    # 确保 /swapfile 不再被使用
                    swapoff /swapfile

                    # 删除旧的 /swapfile
                    rm -f /swapfile

                    # 创建新的 swap 分区
                    dd if=/dev/zero of=/swapfile bs=1M count=$new_swap
                    chmod 600 /swapfile
                    mkswap /swapfile
                    swapon /swapfile

                    echo "虚拟内存大小已调整为${new_swap}MB"
                    ;;
                [Nn])
                    echo "已取消"
                    ;;
                *)
                    echo "无效的选择，请输入 Y 或 N。"
                    ;;
                esac
                ;;
            
            13)
                clear

                RED="\033[31m"
                GREEN="\033[32m"
                YELLOW="\033[33m"
                NC="\033[0m"

                # 系统检测
                OS=$(cat /etc/os-release | grep -o -E "Debian|Ubuntu|CentOS" | head -n 1)

                if [[ $OS == "Debian" || $OS == "Ubuntu" || $OS == "CentOS" ]]; then
                    echo -e "检测到你的系统是 ${YELLOW}${OS}${NC}"
                else
                    echo -e "${RED}很抱歉，你的系统不受支持！${NC}"
                    exit 1
                fi

                # 检测安装Python3的版本
                VERSION=$(python3 -V 2>&1 | awk '{print $2}')

                # 获取最新Python3版本
                PY_VERSION=$(curl -s https://www.python.org/ | grep "downloads/release" | grep -o 'Python [0-9.]*' | grep -o '[0-9.]*')

                # 卸载Python3旧版本
                if [[ $VERSION == "3"* ]]; then
                    echo -e "${YELLOW}你的Python3版本是${NC}${RED}${VERSION}${NC}，${YELLOW}最新版本是${NC}${RED}${PY_VERSION}${NC}"
                    read -p "是否确认升级最新版Python3？默认不升级 [y/N]: " CONFIRM
                    if [[ $CONFIRM == "y" ]]; then
                        if [[ $OS == "CentOS" ]]; then
                            echo ""
                            rm-rf /usr/local/python3* >/dev/null 2>&1
                        else
                            apt --purge remove python3 python3-pip -y
                            rm-rf /usr/local/python3*
                        fi
                    else
                        echo -e "${YELLOW}已取消升级Python3${NC}"
                        exit 1
                    fi
                else
                    echo -e "${RED}检测到没有安装Python3。${NC}"
                    read -p "是否确认安装最新版Python3？默认安装 [Y/n]: " CONFIRM
                    if [[ $CONFIRM != "n" ]]; then
                        echo -e "${GREEN}开始安装最新版Python3...${NC}"
                    else
                        echo -e "${YELLOW}已取消安装Python3${NC}"
                        exit 1
                    fi
                fi

                # 安装相关依赖
                if [[ $OS == "CentOS" ]]; then
                    yum update
                    yum groupinstall -y "development tools"
                    yum install wget openssl-devel bzip2-devel libffi-devel zlib-devel -y
                else
                    apt update
                    apt install wget build-essential libreadline-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev -y
                fi

                # 安装python3
                cd /root/
                wget https://www.python.org/ftp/python/${PY_VERSION}/Python-"$PY_VERSION".tgz
                tar -zxf Python-${PY_VERSION}.tgz
                cd Python-${PY_VERSION}
                ./configure --prefix=/usr/local/python3
                make -j $(nproc)
                make install
                if [ $? -eq 0 ];then
                    rm -f /usr/local/bin/python3*
                    rm -f /usr/local/bin/pip3*
                    ln -sf /usr/local/python3/bin/python3 /usr/bin/python3
                    ln -sf /usr/local/python3/bin/pip3 /usr/bin/pip3
                    clear
                    echo -e "${YELLOW}Python3安装${GREEN}成功，${NC}版本为: ${NC}${GREEN}${PY_VERSION}${NC}"
                else
                    clear
                    echo -e "${RED}Python3安装失败！${NC}"
                    exit 1
                fi
                cd /root/ && rm -rf Python-${PY_VERSION}.tgz && rm -rf Python-${PY_VERSION}
                ;;
            14)
                clear
                if [ -f "/etc/debian_version" ]; then
                    # Debian-based systems
                    apt autoremove --purge -y
                    apt clean -y
                    apt autoclean -y
                    apt remove --purge $(dpkg -l | awk '/^rc/ {print $2}') -y
                    journalctl --rotate
                    journalctl --vacuum-time=1s
                    journalctl --vacuum-size=50M
                    apt remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-.*//') | xargs) -y
                elif [ -f "/etc/redhat-release" ]; then
                    # Red Hat-based systems
                    yum autoremove -y
                    yum clean all
                    journalctl --rotate
                    journalctl --vacuum-time=1s
                    journalctl --vacuum-size=50M
                    yum remove $(rpm -q kernel | grep -v $(uname -r)) -y
                fi
                ;;
            15)
                clear
                echo "请备份数据，将为你重装系统，预计花费15分钟。"
                read -p "确定继续吗？(Y/N): " choice

                case "$choice" in
                    [Yy])
                    while true; do
                        read -p "请选择要重装的系统:  1. Debian12 | 2. Ubuntu20.04 : " sys_choice

                        case "$sys_choice" in
                        1)
                            xitong="-d 12"
                            break  # 结束循环
                            ;;
                        2)
                            xitong="-u 20.04"
                            break  # 结束循环
                            ;;
                        *)
                            echo "无效的选择，请重新输入。"
                            ;;
                        esac
                    done

                    read -p "请输入你重装后的密码: " vpspasswd
                    if command -v apt &>/dev/null; then
                        apt update -y && apt install -y wget
                    elif command -v yum &>/dev/null; then
                        yum -y update && yum -y install wget
                    else
                        echo "未知的包管理器!"
                    fi
                    bash <(wget --no-check-certificate -qO- 'https://raw.githubusercontent.com/MoeClub/Note/master/InstallNET.sh') $xitong -v 64 -p $vpspasswd -port 22
                    ;;
                    [Nn])
                    echo "已取消"
                    ;;
                    *)
                    echo "无效的选择，请输入 Y 或 N。"
                    ;;
                    esac
                    ;;
            0)
                cd ~
                ./tse.sh
                exit
                ;;

            00)
                exit
                ;;

            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear
        done
        ;;

    4)
        clear
        while true; do
            echo " ▼ "
            echo "安装常用工具"
            echo "------------------------"
            echo "1.  套餐一： sudo / curl / wget / nano"
            echo "2.  套餐二： sudo / curl / wget / nano / tar / socat"
            echo "3.  套餐三： htop / iftop / unzip / tmux / ffmpeg"
            echo "------------------------"
            echo "4.  手动安装指定工具 ▶"
            echo "------------------------"
            echo "51. 全部安装"
            echo "50. 全部卸载"
            echo "------------------------"
            echo "0.  返回主菜单"
            echo "00. 退出脚本"
            echo "------------------------"
            read -p "请输入你的选择: " sub_choice

        case $sub_choice in
            1)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y sudo curl wget nano
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install sudo curl wget nano
                else
                    echo "未知的包管理器!"
                fi

                ;;
            2)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y sudo curl wget nano tar socat
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install sudo curl wget nano tar socat
                else
                    echo "未知的包管理器!"
                fi
                ;;
            3)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y htop iftop unzip tmux ffmpeg
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install htop iftop unzip tmux ffmpeg
                else
                    echo "未知的包管理器!"
                fi
                ;;
            4)
                clear
                echo " ▼ "
                echo "安装常用工具 - 手动安装指定工具"
                while true; do
                    # 提示用户输入工具名称
                    read -p "请输入要安装的工具名称（输入 'cancel' 取消安装）: " tool_name

                    # 检查用户输入是否为空
                    if [[ -z "$tool_name" ]]; then
                        echo "错误：工具名称不能为空，请重新输入。"
                    elif [[ "$tool_name" == "cancel" ]]; then
                        echo "安装已取消。"
                        break  # 退出当前 case 分支
                    else
                        # 检查系统包管理器并安装指定工具
                        if command -v apt &>/dev/null; then
                            if sudo apt update -y && sudo apt install -y "$tool_name"; then
                                echo "$tool_name 工具已安装成功。"
                                break  # 退出当前 case 分支
                            else
                                echo "错误：未找到安装包 '$tool_name'。"
                                break  # 退出当前 case 分支
                            fi
                        elif command -v yum &>/dev/null; then
                            if sudo yum -y update && sudo yum -y install "$tool_name"; then
                                echo "$tool_name 工具已安装成功。"
                                break  # 退出当前 case 分支
                            else
                                echo "错误：未找到安装包 '$tool_name'。"
                                break  # 退出当前 case 分支
                            fi
                        else
                            echo "未知的包管理器!"
                            exit 1
                        fi
                    fi
                done
                ;;
            5)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y htop
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install htop
                else
                    echo "未知的包管理器!"
                fi
                ;;
            6)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y iftop
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install iftop
                else
                    echo "未知的包管理器!"
                fi
                ;;
            7)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y unzip
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install unzip
                else
                    echo "未知的包管理器!"
                fi
                ;;
            8)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y tar
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install tar
                else
                    echo "未知的包管理器!"
                fi
                ;;
            9)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y tmux
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install tmux
                else
                    echo "未知的包管理器!"
                fi
                ;;
            10)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y ffmpeg
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install ffmpeg
                else
                    echo "未知的包管理器!"
                fi
                ;;

            51)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y curl wget sudo socat htop iftop unzip tar tmux ffmpeg
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install curl wget sudo socat htop iftop unzip tar tmux ffmpeg
                else
                    echo "未知的包管理器!"
                fi
                ;;

            50)
                clear
                if command -v apt &>/dev/null; then
                    apt remove -y htop iftop unzip tmux ffmpeg
                elif command -v yum &>/dev/null; then
                    yum -y remove htop iftop unzip tmux ffmpeg
                else
                    echo "未知的包管理器!"
                fi
                ;;

            0)
                cd ~
                ./tse.sh
                exit
                ;;

            00)
                exit
                ;;

            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear

        done
        ;;

    5)
        clear
        while true; do
            echo " ▼ "
            echo "安装常用工具"
            echo "------------------------"
            echo "1.  BBR"
            echo "2.  WARP"
            echo "------------------------"
            echo "0.  返回主菜单"
            echo "00. 退出脚本"
            echo "------------------------"
            read -p "请输入你的选择: " sub_choice

        case $sub_choice in
            1)
                clear
                echo " ▼ "
                echo "安装常用工具 - BBR"
                # 检查并安装 wget（如果需要）
                if ! command -v wget &>/dev/null; then
                    if command -v apt &>/dev/null; then
                        apt update -y && apt install -y wget
                    elif command -v yum &>/dev/null; then
                        yum -y update && yum -y install wget
                    else
                        echo "未知的包管理器!"
                        exit 1
                    fi
                fi
                wget --no-check-certificate -O tcpx.sh https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
                chmod +x tcpx.sh
                bash tcpx.sh
                #bakcup:
                if [ ! -d "/usr/tse" ]; then
                    sudo mkdir -p /usr/tse
                fi
                mv tcpx.sh /usr/tse/
                ;;
            
            2)
                clear
                echo " ▼ "
                echo "安装常用工具 - WARP"
                # 检查并安装 wget（如果需要）
                if ! command -v wget &>/dev/null; then
                    if command -v apt &>/dev/null; then
                        apt update -y && apt install -y wget
                    elif command -v yum &>/dev/null; then
                        yum -y update && yum -y install wget
                    else
                        echo "未知的包管理器!"
                        exit 1
                    fi
                fi
                # wget -N https://raw.githubusercontent.com/fscarmen/warp/main/menu.sh && bash menu.sh [option] [lisence]
                wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh [option] [lisence/url/token]
                #bakcup:
                if [ ! -d "/usr/tse" ]; then
                    sudo mkdir -p /usr/tse
                fi
                mv menu.sh /usr/tse/
                ;;

            0)
                cd ~
                ./tse.sh
                exit
                ;;

            00)
                exit
                ;;

            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear

        done
        ;;
    6)
        clear
        while true; do

        echo " ▼ "
        echo "测试脚本合集"
        echo "------------------------"
        echo "1.  ChatGPT解锁状态检测"
        echo "2.  流媒体解锁测试"
        echo "3.  TikTok状态检测"
        echo "4.  三网回程延迟路由测试"
        echo "5.  三网回程线路测试"
        echo "6.  三网专项测速"
        echo "7.  VPS性能专项测试"
        echo "8.  VPS性能全局测试"
        echo "------------------------"
        echo "0.  返回主菜单"
        echo "00. 退出脚本"
        echo "------------------------"
        read -p "请输入你的选择: " sub_choice

        # if [ ! -d "~/tse" ]; then
        #     sudo mkdir -p ~/tse
        # fi

        case $sub_choice in
            1)
                clear
                bash <(curl -Ls https://cdn.jsdelivr.net/gh/missuo/OpenAI-Checker/openai.sh)
                # bash <(curl -Ls https://cdn.jsdelivr.net/gh/missuo/OpenAI-Checker/openai.sh) -o ~/tse/openai.sh
                ;;
            2)
                clear
                bash <(curl -L -s check.unlock.media)
                rm bahamut_cookie.txt
                ;;
            3)
                clear
                wget -qO- https://github.com/yeahwu/check/raw/main/check.sh | bash
                # wget -qO- https://github.com/yeahwu/check/raw/main/check.sh -O ~/tse/ | bash ~/tse/check.sh
                ;;
            4)
                clear
                wget -qO- git.io/besttrace | bash
                # wget -qO- git.io/besttrace -O ~/tse/ | bash ~/tse/besttrace
                rm besttrace*
                ;;
            5)
                clear
                curl https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh | bash
                # curl https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh -o ~/tse/ | bash ~/tse/mtr_trace.sh
                ;;
            6)
                clear
                bash <(curl -Lso- https://git.io/superspeed_uxh)
                # bash <(curl -Lso- https://git.io/superspeed_uxh) -o ~/tse/superspeed_uxh
                ;;
            7)
                clear
                curl -sL yabs.sh | bash -s -- -i -5
                ;;
            8)
                clear
                wget -qO- bench.sh | bash
                ;;
            0)
                cd ~
                ./tse.sh
                exit
                ;;
            00)
                exit
                ;;
            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear
        done
        ;;

    7)
        clear
        while true; do
            echo " ▼ "
            echo "Docker管理器"
            echo "------------------------"
            echo "1.  安装/更新 Docker 环境"
            echo "2.  Dcoker 全局总览"
            echo "------------------------"
            echo "3.  Dcoker 容器管理 ▶"
            echo "4.  Dcoker 镜像管理 ▶"
            echo "5.  Dcoker 网络管理 ▶"
            echo "6.  Dcoker 卷管理 ▶"
            echo "------------------------"
            echo "7.  Dcoker-compose 管理"
            echo "------------------------"
            echo "8.  清理无用的 Docker 容器和镜像网络数据卷"
            echo "------------------------"
            echo "9.  卸载 Dcoker 环境"
            echo "------------------------"
            echo "10.  Docker 库管理 ▶"
            echo "------------------------"
            echo "0.  返回主菜单"
            echo "00. 退出脚本"
            echo "------------------------"
            read -p "请输入你的选择: " sub_choice

        case $sub_choice in
            1)
                clear
                curl -fsSL https://get.docker.com | sh
                systemctl start docker
                systemctl enable docker
                curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose
                ;;
            2)
                if ! command -v docker &> /dev/null; then
                    echo "未检测到 Docker，请先安装 Docker。"
                elif ! docker info &> /dev/null; then
                    echo "Docker 程序未开启，请先启动 Docker 守护程序。"
                else
                    echo "Docker 版本"
                    docker --version
                    docker-compose --version
                    echo ""
                    echo "Docker 镜像列表"
                    docker image ls
                    echo ""
                    echo "Docker 容器列表"
                    docker ps -a
                    echo ""
                    echo "Docker 卷列表"
                    docker volume ls
                    echo ""
                    echo "Docker 网络列表"
                    docker network ls
                    echo ""
                fi
                ;;
            3)
                while true; do
                    clear
                    echo "Docker容器列表"
                    docker ps -a
                    echo ""
                    echo "容器操作"
                    echo "------------------------"
                    echo "1. 创建新的容器"
                    echo "------------------------"
                    echo "2. 启动指定容器             6. 启动所有容器"
                    echo "3. 停止指定容器             7. 暂停所有容器"
                    echo "4. 删除指定容器             8. 删除所有容器"
                    echo "5. 重启指定容器             9. 重启所有容器"
                    echo "------------------------"
                    echo "11. 进入指定容器           12. 查看容器日志           13. 查看容器网络"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            read -p "请输入创建命令: " dockername
                            $dockername
                            ;;

                        2)
                            read -p "请输入容器名: " dockername
                            docker start $dockername
                            ;;
                        3)
                            read -p "请输入容器名: " dockername
                            docker stop $dockername
                            ;;
                        4)
                            read -p "请输入容器名: " dockername
                            docker rm -f $dockername
                            ;;
                        5)
                            read -p "请输入容器名: " dockername
                            docker restart $dockername
                            ;;
                        6)
                            docker start $(docker ps -a -q)
                            ;;
                        7)
                            docker stop $(docker ps -q)
                            ;;
                        8)
                            read -p "确定删除所有容器吗？(Y/N): " choice
                            case "$choice" in
                                [Yy])
                                docker rm -f $(docker ps -a -q)
                                ;;
                                [Nn])
                                ;;
                                *)
                                echo "无效的选择，请输入 Y 或 N。"
                                ;;
                            esac
                            ;;
                        9)
                            docker restart $(docker ps -q)
                            ;;
                        11)
                            read -p "请输入容器名: " dockername
                            docker exec -it $dockername /bin/bash
                            ;;
                        12)
                            read -p "请输入容器名: " dockername
                            docker logs $dockername
                            echo -e "\033[0;32m操作完成\033[0m"
                            echo "按任意键继续..."
                            read -n 1 -s -r -p ""
                            echo ""
                            clear
                            ;;
                        13)
                            echo ""
                            container_ids=$(docker ps -q)

                            echo "------------------------------------------------------------"
                            printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

                            for container_id in $container_ids; do
                                container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

                                container_name=$(echo "$container_info" | awk '{print $1}')
                                network_info=$(echo "$container_info" | cut -d' ' -f2-)

                                while IFS= read -r line; do
                                    network_name=$(echo "$line" | awk '{print $1}')
                                    ip_address=$(echo "$line" | awk '{print $2}')

                                    printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                                done <<< "$network_info"
                            done

                            echo -e "\033[0;32m操作完成\033[0m"
                            echo "按任意键继续..."
                            read -n 1 -s -r -p ""
                            echo ""
                            clear
                            ;;

                        0)
                            break  # 跳出循环，退出菜单
                            ;;

                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
                done
                ;;
            4)
                while true; do
                    clear
                    echo "Docker镜像列表"
                    docker image ls
                    echo ""
                    echo "镜像操作"
                    echo "------------------------"
                    echo "1. 获取指定镜像             3. 删除指定镜像"
                    echo "2. 更新指定镜像             4. 删除所有镜像"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            read -p "请输入镜像名: " dockername
                            docker pull $dockername
                            ;;
                        2)
                            read -p "请输入镜像名: " dockername
                            docker pull $dockername
                            ;;
                        3)
                            read -p "请输入镜像名: " dockername
                            docker rmi -f $dockername
                            ;;
                        4)
                            read -p "确定删除所有镜像吗？(Y/N): " choice
                            case "$choice" in
                                [Yy])
                                docker rmi -f $(docker images -q)
                                ;;
                                [Nn])

                                ;;
                                *)
                                echo "无效的选择，请输入 Y 或 N。"
                                ;;
                            esac
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;

                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
                done
                ;;

            5)
                while true; do
                    clear
                    echo "Docker网络列表"
                    echo "------------------------------------------------------------"
                    docker network ls
                    echo ""

                    echo "------------------------------------------------------------"
                    container_ids=$(docker ps -q)
                    printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

                    for container_id in $container_ids; do
                        container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

                        container_name=$(echo "$container_info" | awk '{print $1}')
                        network_info=$(echo "$container_info" | cut -d' ' -f2-)

                        while IFS= read -r line; do
                            network_name=$(echo "$line" | awk '{print $1}')
                            ip_address=$(echo "$line" | awk '{print $2}')

                            printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
                        done <<< "$network_info"
                    done

                    echo ""
                    echo "网络操作"
                    echo "------------------------"
                    echo "1. 创建网络"
                    echo "2. 加入网络"
                    echo "3. 退出网络"
                    echo "4. 删除网络"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            read -p "设置新网络名: " dockernetwork
                            docker network create $dockernetwork
                            ;;
                        2)
                            read -p "加入网络名: " dockernetwork
                            read -p "那些容器加入该网络: " dockername
                            docker network connect $dockernetwork $dockername
                            echo ""
                            ;;
                        3)
                            read -p "退出网络名: " dockernetwork
                            read -p "那些容器退出该网络: " dockername
                            docker network disconnect $dockernetwork $dockername
                            echo ""
                            ;;

                        4)
                            read -p "请输入要删除的网络名: " dockernetwork
                            docker network rm $dockernetwork
                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;

                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
                done
                ;;

            6)
                while true; do
                    clear
                    echo "Docker卷列表"
                    docker volume ls
                    echo ""
                    echo "卷操作"
                    echo "------------------------"
                    echo "1. 创建新卷"
                    echo "2. 删除卷"
                    echo "------------------------"
                    echo "0. 返回上一级选单"
                    echo "------------------------"
                    read -p "请输入你的选择: " sub_choice

                    case $sub_choice in
                        1)
                            read -p "设置新卷名: " dockerjuan
                            docker volume create $dockerjuan

                            ;;
                        2)
                            read -p "输入删除卷名: " dockerjuan
                            docker volume rm $dockerjuan

                            ;;
                        0)
                            break  # 跳出循环，退出菜单
                            ;;

                        *)
                            break  # 跳出循环，退出菜单
                            ;;
                    esac
                done
                ;;
            7)
                DOCKER_DIR="/root/docker"

                function list_docker_compose_services() {
                    echo "当前的 Docker-compose 服务:"
                    echo ""
                    all_services=$(find "$DOCKER_DIR" -mindepth 1 -maxdepth 1 -type d | sed 's!.*/!!')
                    
                    index=1
                    for service in $all_services; do
                        display_name="\033[0;34m$index\033[0m -- $service"
                        service_path="${DOCKER_DIR}/${service}"
                        
                        # 检查服务是否正在运行
                        ps_output=$(docker-compose -f "$service_path/docker-compose.yml" ps 2>/dev/null)
                        if [ $? -ne 0 ]; then
                            # 如果yml格式文件不存在，尝试yaml格式
                            ps_output=$(docker-compose -f "$service_path/docker-compose.yaml" ps 2>/dev/null)
                        fi
                        
                        # 检查docker-compose ps输出是否符合正常格式，并且下面有具体服务信息
                        if echo "$ps_output" | grep -q "NAME\s*IMAGE\s*COMMAND\s*SERVICE\s*CREATED\s*STATUS\s*PORTS" \
                            && echo "$ps_output" | grep -qE "\b[0-9]+\b\s+[a-zA-Z0-9_-]+\s+"; then
                            display_name="$display_name   \033[0;35m*running\033[0m"
                        fi
                        
                        echo -e "$display_name"
                        ((index++))
                    done
                    echo "================================="
                    echo ""
                }

                while true; do
                    clear
                    echo " ▼ "
                    echo "Dcoker-compose 管理"
                    list_docker_compose_services
                    echo "Docker 服务管理菜单:"
                    echo "------------------------"
                    echo "1.  创建 Docker-compose 服务"
                    echo "2.  修改 Docker-compose 文件"
                    echo "------------------------"
                    echo "3.  启动 Docker-compose 服务"
                    echo "4.  停止 Docker-compose 服务"
                    echo "5.  重启 Docker-compose 服务"
                    echo "6.  升级 Docker-compose 服务"
                    echo "------------------------"
                    echo "7.  查询 Docker-compose 日志"
                    echo "------------------------"
                    echo "8.  删除 Docker-compose 服务"
                    echo "------------------------"
                    echo "9.  修改文件夹路径（ $DOCKER_DIR ）"
                    echo "------------------------"
                    echo "0.  返回上级菜单"
                    echo "00. 退出脚本"
                    echo "------------------------"
                    echo ""

                    read -p "请选择操作: " choice

                    case $choice in
                        # 11)
                        #     clear
                        #     # 列出所有 Docker-compose 服务
                        #     #list_docker_compose_services
                        #     ;;
                        1)
                            clear
                            list_docker_compose_services
                            # 创建新 Docker-compose 服务
                            read -p "请输入新服务的名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            mkdir -p "$service_dir"
                            touch "$service_dir/docker-compose.yaml"
                            # echo "version: '3'" > "$service_dir/docker-compose.yaml"
                            # echo "services:" >> "$service_dir/docker-compose.yaml"
                            echo "#" > "$service_dir/docker-compose.yaml"
                            echo "新服务 '$service_name' 已创建。"
                            list_docker_compose_services
                            ;;
                        2)
                            clear
                            # 修改 Docker Compose 文件
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要修改的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                nano "$compose_file"
                                echo "Docker Compose 文件已修改。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        3)
                            clear
                            # 启动 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            #find "$DOCKER_DIR" -mindepth 1 -maxdepth 1 -type d | sed 's!.*/!!' | sed 's/^/|-- /'
                            read -p "请输入要启动的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                docker-compose -f "$compose_file" up -d
                                echo "服务 '$service_name' 已启动。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        4)
                            clear
                            # 停止 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要停止的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                docker-compose -f "$compose_file" down
                                echo "服务 '$service_name' 已停止。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        5)
                            clear
                            # 重启 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要重启的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                docker-compose -f "$compose_file" restart
                                echo "服务 '$service_name' 已重启。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        6)
                            clear
                            # 升级 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要升级的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                docker-compose -f "$compose_file" down
                                image_name=$(grep -m1 '^\s*image:' "$compose_file" | awk '{print $2}')
                                # 删除 Docker 镜像
                                if [ -n "$image_name" ]; then
                                    docker rmi $image_name
                                    echo "Docker 镜像 '$image_name' 已删除."
                                else
                                    echo "无法获取 Docker 镜像名称。"
                                fi
                                docker-compose -f "$compose_file" up -d
                                echo "服务 '$service_name' 已升级。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        7)
                            clear
                            # 查询 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要查询的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            compose_file="$service_dir/docker-compose.yaml"
                            if [ -f "$compose_file" ]; then
                                docker-compose -f "$compose_file" logs
                                read -r
                                echo "服务 '$service_name' 日志查询完毕。"
                            else
                                echo "错误：服务 '$service_name' 的 Docker Compose 文件不存在。"
                            fi
                            ;;
                        8)
                            clear
                            # 删除 Docker 服务
                            echo "可用的 Docker 服务:"
                            list_docker_compose_services
                            read -p "请输入要删除的服务名称: " service_name
                            service_dir="$DOCKER_DIR/$service_name"
                            if [ -d "$service_dir" ]; then
                                rm -r "$service_dir"
                                echo "服务 '$service_name' 已删除。"
                            else
                                echo "错误：服务 '$service_name' 不存在。"
                            fi
                            ;;
                        9)
                            clear
                            # 修改自定义文件夹路径
                            read -p "请输入新的自定义文件夹路径: " custom_dir
                            if [ -d "$custom_dir" ]; then
                                DOCKER_DIR="$custom_dir"
                                echo "自定义文件夹路径已修改为: $DOCKER_DIR"
                            else
                                read -p "指定的文件夹路径不存在，是否要创建该文件夹？(Y/N): " create_folder
                                if [ "$create_folder" = "Y" ] || [ "$create_folder" = "y" ]; then
                                    mkdir -p "$custom_dir"
                                    DOCKER_DIR="$custom_dir"
                                    echo "文件夹已创建，并且自定义文件夹路径已修改为: $DOCKER_DIR"
                                else
                                    echo "未创建文件夹，自定义文件夹路径未修改。"
                                fi
                            fi
                            ;;
                        0)
                            # 退出
                            break  # 跳出循环，退出菜单
                            ;;
                        00)
                            exit
                            ;;
                        *)
                            echo "错误：无效的选项，请重新选择。"
                            ;;
                    esac
                done
                ;;
            8)
                clear
                read -p "确定清理无用的镜像容器网络吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    docker system prune -af --volumes
                    ;;
                    [Nn])
                    ;;
                    *)
                    echo "无效的选择，请输入 Y 或 N。"
                    ;;
                esac
                ;;
            9)
                clear
                read -p "确定卸载docker环境吗？(Y/N): " choice
                case "$choice" in
                    [Yy])
                    docker rm $(docker ps -a -q) && docker rmi $(docker images -q) && docker network prune
                    apt-get remove docker -y
                    apt-get remove docker-ce -y
                    apt-get purge docker-ce -y
                    rm -rf /var/lib/docker
                    ;;
                    [Nn])
                    ;;
                    *)
                    echo "无效的选择，请输入 Y 或 N。"
                    ;;
                esac
                ;;
            10)
                while true; do
                    clear
                    echo "Docker镜像列表"
                    docker images
                    echo ""
                    echo "Docker库管理"
                    echo "------------------------"
                    echo "1. Docker Hub登入"
                    echo "2. Docker Hub登出"
                    echo "3. 推送现有镜像"
                    echo "0. 返回主菜单"
                    echo "------------------------"
                    read -p "请输入选项： " choice

                    case $choice in
                        1)
                            # Docker Hub登录
                            docker login
                            ;;
                        2)
                            # Docker Hub登出
                            docker logout
                            ;;
                        3)
                            # 推送现有镜像
                            read -p "请输入要推送的镜像名称（包括仓库和标签，例如myrepo/myimage:latest）: " image_name
                            docker push $image_name
                            ;;
                        0)
                            # 返回主菜单
                            break
                            ;;
                        *)
                            echo "无效的选项，请重新输入。"
                            ;;
                    esac
                done
                ;;
            0)
                cd ~
                ./tse.sh
                exit
                ;;
            00)
                exit
                ;;
            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear
        done
        ;;

    8)
        clear
        while true; do
        echo " ▼ "
        echo "我的工作区"
        echo "系统将为你提供5个后台运行的工作区，你可以用来执行长时间的任务"
        echo "即使你断开SSH，工作区中的任务也不会中断，非常方便！来试试吧！"
        echo -e "\033[33m注意: 进入工作区后使用Ctrl+b再单独按d，退出工作区！\033[0m"
        echo "------------------------"
        echo "a.  安装工作区环境"
        echo "------------------------"
        echo "1.  1号工作区"
        echo "2.  2号工作区"
        echo "3.  3号工作区"
        echo "4.  4号工作区"
        echo "5.  5号工作区"
        echo "------------------------"
        echo "8.  工作区状态"
        echo "------------------------"
        echo "0.  返回主菜单"
        echo "00. 退出脚本"
        echo "------------------------"
        read -p "请输入你的选择: " sub_choice

        case $sub_choice in
            a)
                clear
                if command -v apt &>/dev/null; then
                    apt update -y && apt install -y tmux
                elif command -v yum &>/dev/null; then
                    yum -y update && yum -y install tmux
                else
                    echo "未知的包管理器!"
                fi

                ;;
            1)
                clear
                SESSION_NAME="work1"

                # Check if the session already exists
                tmux has-session -t $SESSION_NAME 2>/dev/null

                # $? is a special variable that holds the exit status of the last executed command
                if [ $? != 0 ]; then
                    # Session doesn't exist, create a new one
                    tmux new -s $SESSION_NAME
                else
                    # Session exists, attach to it
                    tmux attach-session -t $SESSION_NAME
                fi
                ;;
            2)
                clear
                SESSION_NAME="work2"

                # Check if the session already exists
                tmux has-session -t $SESSION_NAME 2>/dev/null

                # $? is a special variable that holds the exit status of the last executed command
                if [ $? != 0 ]; then
                    # Session doesn't exist, create a new one
                    tmux new -s $SESSION_NAME
                else
                    # Session exists, attach to it
                    tmux attach-session -t $SESSION_NAME
                fi
                ;;
            3)
                clear
                SESSION_NAME="work3"

                # Check if the session already exists
                tmux has-session -t $SESSION_NAME 2>/dev/null

                # $? is a special variable that holds the exit status of the last executed command
                if [ $? != 0 ]; then
                    # Session doesn't exist, create a new one
                    tmux new -s $SESSION_NAME
                else
                    # Session exists, attach to it
                    tmux attach-session -t $SESSION_NAME
                fi
                ;;
            4)
                clear
                SESSION_NAME="work4"

                # Check if the session already exists
                tmux has-session -t $SESSION_NAME 2>/dev/null

                # $? is a special variable that holds the exit status of the last executed command
                if [ $? != 0 ]; then
                    # Session doesn't exist, create a new one
                    tmux new -s $SESSION_NAME
                else
                    # Session exists, attach to it
                    tmux attach-session -t $SESSION_NAME
                fi
                ;;
            5)
                clear
                SESSION_NAME="work5"

                # Check if the session already exists
                tmux has-session -t $SESSION_NAME 2>/dev/null

                # $? is a special variable that holds the exit status of the last executed command
                if [ $? != 0 ]; then
                    # Session doesn't exist, create a new one
                    tmux new -s $SESSION_NAME
                else
                    # Session exists, attach to it
                    tmux attach-session -t $SESSION_NAME
                fi
                ;;

            8)
                clear
                tmux list-sessions
                ;;
            0)
                cd ~
                ./tse.sh
                exit
                ;;
            00)
                exit
                ;;
            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear
        done
        ;;

    9)
        clear
        while true; do
            echo " ▼ "
            echo "其它设置"
            echo "------------------------"
            echo "1.  ubuntu区域语言(locale)中文设置"
            echo "2.  禁止screen改变窗口大小"
            echo "------------------------"
            echo "0.  返回主菜单"
            echo "00. 退出脚本"
            echo "------------------------"
            read -p "请输入你的选择: " sub_choice
        case $sub_choice in
            1)
                # Backup function
                backup_file() {
                    if [ -f "$1" ]; then
                        sudo mv "$1" "$1.bak"
                        echo "备份 $1 为 $1.bak"
                    fi
                }

                # Check and create directory if not exists
                check_and_create_directory() {
                    if [ ! -d "$1" ]; then
                        sudo mkdir -p "$1"
                        echo "创建目录 $1"
                    fi
                }

                # Step 1: Check and create directory, backup and edit supported locales file
                check_and_create_directory "/var/lib/locales/supported.d"
                backup_file "/var/lib/locales/supported.d/local"
                echo -e 'zh_CN.UTF-8 UTF-8\nzh_CN GB2312\nzh_CN.GBK GBK\nen_US.UTF-8 UTF-8\nfr_FR ISO-8859-1\nzh_CN.GB18030 GB18030' | sudo tee "/var/lib/locales/supported.d/local" > /dev/null

                # Step 2: Generate locales
                sudo locale-gen --purge

                # Step 3: Check and create directory, backup and edit default locale file
                check_and_create_directory "/etc/default"
                backup_file "/etc/default/locale"
                echo -e 'LANG="zh_CN.UTF-8"\nLANGUAGE="zh_CN:zh"\nLC_ALL="zh_CN.UTF-8"' | sudo tee "/etc/default/locale" > /dev/null

                # Print success message
                echo "乱码问题已经处理完毕。请运行命令 'locale' 检查设置是否生效，建议重启电脑以使改变生效。"

                # sleep 2
                ;;

            2)
                if [ -e /etc/screenrc ]; then
                    # 在文件中查找termcapinfo xterm 'is=
                    if grep -q "termcapinfo xterm 'is=" /etc/screenrc; then
                        # 如果找到了特定行，执行替换操作（保留后面的内容）
                        sed -i "s/termcapinfo xterm 'is=/termcapinfo xterm* 'is=/" /etc/screenrc
                        echo "已经成功在/etc/screenrc文件中修改了特定行。"
                    elif grep -q "termcapinfo xterm* 'is=" /etc/screenrc; then
                        # 如果找到了termcapinfo xterm* 'is=，输出提示信息
                        echo "内容已经存在，请手动查询文件/etc/screenrc。"
                    else
                        # 如果两者都不存在，添加新行
                        # echo "termcapinfo xterm* 'is=\E[r\E[m\E[2J\E[H\E[?7h\E[?1;4;6l'" >> /etc/screenrc
                        # echo "已经在/etc/screenrc文件中添加了新行。"
                        echo "未发现特定行或已经修改，请手动查询文件/etc/screenrc，并进行以下修改(xterm*)："
                        echo "termcapinfo xterm* 'is=\E[r\E[m\E[2J\E[H\E[?7h\E[?1;4;6l'"
                    fi
                else
                    # 如果文件不存在，输出提示信息
                    echo "/etc/screenrc 文件不存在。"
                fi
                ;;

            0)
                cd ~
                ./tse.sh
                exit
                ;;

            00)
                exit
                ;;

            *)
                echo "无效的输入!"
                ;;
        esac
        echo -e "\033[0;32m操作完成\033[0m"
        echo "按任意键继续..."
        read -n 1 -s -r -p ""
        echo ""
        clear

        done
        ;;
    10)
        cd ~/ && curl -sS -O https://raw.githubusercontent.com/ieiian/shell/main/tse.sh && chmod +x tse.sh && ./tse.sh
        exit
        ;;
    0)
        exit
        ;;
    00)
        exit
        ;;
    *)
        echo "无效的输入!"

esac
echo -e "\033[0;32m操作完成\033[0m"
echo "按任意键继续..."
read -n 1 -s -r -p ""
echo ""
clear
done
