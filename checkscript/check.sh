#!/bin/bash
# 综合系统巡检工具
# 功能整合：安全检测、性能监控、环境变量检查、句柄分析、服务状态监控等
# 使用前请以root权限运行，建议定期执行（如每日/每周）

# 检测当前终端是否支持颜色
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null)" -ge 8 ]; then
    # 支持颜色的终端
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # 无颜色
else
    # 不支持颜色或非交互式终端，使用空字符串
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# 浮点数比较函数（兼容性更好）
compare_float() {
    # 参数: $1=值1 $2=操作符(> < >= <=) $3=值2
    local val1="$1"
    local op="$2"
    local val2="$3"
    
    # 将浮点数转换为整数进行比较（乘以100）
    val1_int=$(echo "$val1 * 100" | awk '{printf "%.0f", $1}')
    val2_int=$(echo "$val2 * 100" | awk '{printf "%.0f", $1}')
    
    case "$op" in
        ">")
            [ "$val1_int" -gt "$val2_int" ]
            ;;
        "<")
            [ "$val1_int" -lt "$val2_int" ]
            ;;
        ">=")
            [ "$val1_int" -ge "$val2_int" ]
            ;;
        "<=")
            [ "$val1_int" -le "$val2_int" ]
            ;;
        *)
            return 1
            ;;
    esac
}

# 检查是否以root权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}错误：此脚本需要以root权限运行，请使用sudo或切换到root用户${NC}"
    exit 1
fi

# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    else
        OS="unknown"
    fi
    echo $OS
}

# 检查必要工具是否安装
check_dependencies() {
    OS=$(detect_os)
    dependencies="sysstat net-tools"
    missing=""

    for dep in $dependencies; do
        case $OS in
            ubuntu|debian)
                if ! dpkg -s $dep >/dev/null 2>&1; then
                    missing="$missing $dep"
                fi
                ;;
            centos|rhel|fedora)
                if ! rpm -q $dep >/dev/null 2>&1; then
                    missing="$missing $dep"
                fi
                ;;
            *)
                if ! command -v $dep >/dev/null 2>&1; then
                    missing="$missing $dep"
                fi
                ;;
        esac
    done

    if [ -n "$missing" ]; then
        echo "${YELLOW}检测到缺少必要工具，正在尝试安装...${NC}"
        case $OS in
            ubuntu|debian)
                apt update -y >/dev/null 2>&1
                apt install -y $missing >/dev/null 2>&1
                ;;
            centos|rhel)
                yum install -y $missing >/dev/null 2>&1
                ;;
            fedora)
                dnf install -y $missing >/dev/null 2>&1
                ;;
            *)
                echo "${RED}无法自动安装依赖，请手动安装: $missing${NC}"
                exit 1
                ;;
        esac
    fi
}

# 初始化巡检报告
REPORT_FILE="system_inspection_$(date +%Y%m%d_%H%M%S).log"
echo "系统综合巡检报告 - $(date)" > $REPORT_FILE
echo "" >> $REPORT_FILE

# 添加内容到报告（去除颜色代码）
add_to_report() {
    # 去除ANSI颜色代码
    clean_text=$(echo "$1" | sed 's/\033\[[0-9;]*m//g')
    echo "$clean_text" >> $REPORT_FILE
}

# 显示开始信息
echo "${YELLOW}===== 系统综合巡检工具 ====="
echo "巡检时间: $(date)"
echo "报告将保存至: $REPORT_FILE"
echo "正在检查依赖工具..."
check_dependencies
echo "=================================${NC}"

# 1. 系统基本信息
echo ""
echo "${BLUE}1. 系统基本信息${NC}"
add_to_report "1. 系统基本信息"

# 兼容不同系统的版本信息获取
get_os_info() {
    if [ -f /etc/os-release ]; then
        grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"'
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    elif [ -f /etc/debian_version ]; then
        echo "Debian $(cat /etc/debian_version)"
    else
        uname -o
    fi
}

os_info=$(get_os_info)
kernel_version=$(uname -r)
hostname=$(hostname)
uptime_info=$(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}' | sed 's/^ *//')

# 获取IP地址，兼容不同系统
get_ip_address() {
    # 方法1: hostname -I
    ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$ip_addr" ]; then
        echo $ip_addr
        return
    fi
    
    # 方法2: ip route
    ip_addr=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')
    if [ -n "$ip_addr" ]; then
        echo $ip_addr
        return
    fi
    
    # 方法3: ifconfig
    ip_addr=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | sed 's/addr://')
    if [ -n "$ip_addr" ]; then
        echo $ip_addr
        return
    fi
    
    echo "未获取到"
}

ip_address=$(get_ip_address)

echo "  系统版本: $os_info"
echo "  内核版本: $kernel_version"
echo "  主机名: $hostname"
echo "  IP地址: $ip_address"
echo "  运行时间: $uptime_info"
add_to_report "  系统版本: $os_info"
add_to_report "  内核版本: $kernel_version"
add_to_report "  主机名: $hostname"
add_to_report "  IP地址: $ip_address"
add_to_report "  运行时间: $uptime_info"

# 2. 环境变量安全检测
echo ""
echo "${BLUE}2. 环境变量安全检测${NC}"
echo ""
add_to_report ""
add_to_report "2. 环境变量安全检测"

# 2.1 PATH环境变量分析
echo "  PATH环境变量分析..."
path_var=$PATH
# 使用兼容的方式处理PATH分析
path_count=$(echo "$path_var" | tr ':' '\n' | wc -l)
echo "    PATH包含 $path_count 个路径"
add_to_report "    PATH包含 $path_count 个路径"

dangerous_paths="/ /root /tmp /var/tmp /dev/shm"
echo "$path_var" | tr ':' '\n' | while read -r path; do
    for danger in $dangerous_paths; do
        if [ "$path" = "$danger" ]; then
            echo "${RED}    危险路径: $path (包含在PATH中)${NC}"
            add_to_report "    ${RED}危险路径: $path (包含在PATH中)${NC}"
        fi
    done

    if [ -d "$path" ] && [ -w "$path" ] && ! ls -ld "$path" | grep -qE '^drwxr-xr-x'; then
        echo "${YELLOW}    可写路径: $path (存在非授权写入风险)${NC}"
        add_to_report "    ${YELLOW}可写路径: $path (存在非授权写入风险)${NC}"
    fi
done

# 2.2 敏感环境变量扫描
echo ""
echo "  敏感环境变量扫描..."
sensitive_vars="PASSWORD SECRET KEY TOKEN CREDENTIAL PASS DB_PASS"
found_sensitive=0
for var in $sensitive_vars; do
    matches=$(env | grep -i "$var" | grep -v -E '^SHLVL=|^PWD=|^_=|^LS_COLORS=')
    if [ -n "$matches" ]; then
        found_sensitive=1
        echo "${YELLOW}    潜在敏感变量:${NC}"
        echo "$matches" | awk -F= '{print "      " $1 "=***(内容已隐藏)***"}'
        add_to_report "    ${YELLOW}潜在敏感变量: $var${NC}"
    fi
done
if [ $found_sensitive -eq 0 ]; then
    echo "${GREEN}    未发现明显敏感环境变量${NC}"
    add_to_report "    ${GREEN}未发现明显敏感环境变量${NC}"
fi

# 2.3 环境配置文件检查
echo ""
echo "  环境配置文件权限检查..."
env_files="/etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile"
for file in $env_files; do
    expanded_file=$(eval echo "$file")
    if [ -f "$expanded_file" ]; then
        perms=$(stat -c "%a" "$expanded_file")
        if [ "$perms" -gt 644 ]; then
            echo "${RED}    不安全权限: $expanded_file (权限$perms，建议≤644)${NC}"
            add_to_report "    ${RED}不安全权限: $expanded_file (权限$perms，建议≤644)${NC}"
        else
            echo "    安全权限: $expanded_file (权限$perms)"
            add_to_report "    安全权限: $expanded_file (权限$perms)"
        fi
    fi
done

# 3. 系统句柄数分析
echo "\n${BLUE}3. 系统句柄数分析${NC}"
echo ""
add_to_report ""
add_to_report "3. 系统句柄数分析"

# 3.1 句柄限制配置
echo "  句柄限制配置..."
sys_max_open=$(cat /proc/sys/fs/file-max)
sys_current_max=$(cat /proc/sys/fs/file-nr | awk '{print $1}')
sys_available=$((sys_max_open - sys_current_max))

echo "    系统级最大句柄数: $sys_max_open"
echo "    当前系统已使用句柄: $sys_current_max"
echo "    系统句柄剩余可用: $sys_available"
add_to_report "    系统级最大句柄数: $sys_max_open"
add_to_report "    当前系统已使用句柄: $sys_current_max"
add_to_report "    系统句柄剩余可用: $sys_available"

user_soft=$(ulimit -Sn)
user_hard=$(ulimit -Hn)
echo "    用户级句柄限制(软): $user_soft"
echo "    用户级句柄限制(硬): $user_hard"
add_to_report "    用户级句柄限制(软): $user_soft"
add_to_report "    用户级句柄限制(硬): $user_hard"

usage_rate=$(echo "$sys_current_max $sys_max_open" | awk '{printf "%.2f", $1/$2*100}')
echo "    系统句柄整体使用率: $usage_rate%"
add_to_report "    系统句柄整体使用率: $usage_rate%"

if compare_float "$usage_rate" ">" "80"; then
    echo "${RED}    警告: 系统句柄使用率超过80%，可能面临耗尽风险${NC}"
    add_to_report "    ${RED}警告: 系统句柄使用率超过80%，可能面临耗尽风险${NC}"
fi

# 3.2 进程句柄TOP分析
echo "\n  句柄使用TOP 10进程..."
echo "    排名  PID    句柄数  进程名"
echo "    -------------------------"
add_to_report "    进程句柄使用TOP 10:"
add_to_report "    排名  PID    句柄数  进程名"
add_to_report "    -------------------------"

# 使用/proc文件系统统计句柄，避免lsof的UID警告
rank=0
for pid_dir in /proc/[0-9]*; do
    if [ -d "$pid_dir/fd" ]; then
        pid=$(basename "$pid_dir")
        if [ -d "/proc/$pid" ]; then
            fd_count=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
            if [ "$fd_count" -gt 0 ]; then
                echo "$fd_count $pid"
            fi
        fi
    fi
done | sort -nr | head -10 | while read count pid; do
    if [ -n "$pid" ] && [ "$pid" -gt 0 ]; then
        cmd=$(ps -p $pid -o comm= 2>/dev/null || echo "unknown")
        rank=$(expr $rank + 1)
        printf "    %-5d %-6d %-7d %s\n" $rank $pid $count "$cmd"
        add_to_report "    $rank    $pid    $count    $cmd"
    fi
done

# 4. 系统性能深度检测
echo ""
echo "${BLUE}4. 系统性能检测${NC}"
echo ""
add_to_report ""
add_to_report "4. 系统性能检测"

# 4.1 CPU性能分析
echo "  CPU性能分析..."
cpu_cores=$(grep -c ^processor /proc/cpuinfo)
cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed -e 's/^ *//')

echo "    CPU型号: $cpu_model"
echo "    CPU核心数: $cpu_cores"
add_to_report "    CPU型号: $cpu_model"
add_to_report "    CPU核心数: $cpu_cores"

# 获取CPU使用率（适配CentOS 7）
get_cpu_usage() {
    # 方法1: 使用top命令（兼容性最好）
    cpu_usage=$(top -bn1 | grep "%Cpu" | awk '{print 100 - $8}' | cut -d'%' -f1 2>/dev/null)
    
    # 如果上面方法失败，尝试其他方法
    if [ -z "$cpu_usage" ] || [ "$cpu_usage" = "100" ]; then
        # 方法2: 使用sar命令
        cpu_usage=$(sar -u 1 1 2>/dev/null | awk '/Average:/ {printf "%.2f", 100 - $NF}' 2>/dev/null)
    fi
    
    # 方法3: 使用vmstat
    if [ -z "$cpu_usage" ] || [ "$cpu_usage" = "0.00" ]; then
        cpu_usage=$(vmstat 1 2 2>/dev/null | awk 'NR==4 {printf "%.2f", 100 - $15}' 2>/dev/null)
    fi
    
    # 方法4: 使用/proc/stat计算
    if [ -z "$cpu_usage" ] || [ "$cpu_usage" = "0.00" ]; then
        cpu1=$(cat /proc/stat | head -1 | awk '{print $2+$3+$4+$5+$6+$7+$8}')
        idle1=$(cat /proc/stat | head -1 | awk '{print $5}')
        sleep 1
        cpu2=$(cat /proc/stat | head -1 | awk '{print $2+$3+$4+$5+$6+$7+$8}')
        idle2=$(cat /proc/stat | head -1 | awk '{print $5}')
        
        cpu_diff=$((cpu2 - cpu1))
        idle_diff=$((idle2 - idle1))
        
        if [ $cpu_diff -gt 0 ]; then
            cpu_usage=$(echo "$idle_diff $cpu_diff" | awk '{printf "%.2f", 100 - ($1/$2*100)}')
        fi
    fi
    
    # 如果仍然无法获取，返回默认值
    if [ -z "$cpu_usage" ] || [ "$cpu_usage" = "0.00" ]; then
        echo "未能获取"
    else
        echo "$cpu_usage"
    fi
}

cpu_usage=$(get_cpu_usage)
echo "    CPU平均使用率(5秒): $cpu_usage%"
add_to_report "    CPU平均使用率(5秒): $cpu_usage%"

if compare_float "$cpu_usage" ">" "80"; then
    echo "${RED}    警告: CPU使用率超过80%${NC}"
    add_to_report "    ${RED}警告: CPU使用率超过80%${NC}"
fi

echo ""
echo "    CPU占用TOP5进程:"
ps -eo %cpu,pid,user,comm --sort=-%cpu | head -6 | awk 'NR==1 {print "      " $0} NR>1 {printf "      %.2f%%  %-6d %-8s %s\n", $1, $2, $3, $4}'
add_to_report "    CPU占用TOP5进程:"
ps -eo %cpu,pid,user,comm --sort=-%cpu | head -6 >> $REPORT_FILE

# 4.2 内存性能分析
echo ""
echo "  内存性能分析..."
mem_total=$(free -h | grep Mem | awk '{print $2}')
mem_used=$(free -h | grep Mem | awk '{print $3}')
mem_free=$(free -h | grep Mem | awk '{print $4}')
mem_available=$(free -h | grep Mem | awk '{print $7}')
mem_used_percent=$(free | grep Mem | awk '{printf "%.2f", $3/$2*100}')

echo "    总内存: $mem_total"
echo "    已使用: $mem_used ($mem_used_percent%)"
echo "    空闲内存: $mem_free"
echo "    可用内存: $mem_available"
add_to_report "    总内存: $mem_total"
add_to_report "    已使用: $mem_used ($mem_used_percent%)"
add_to_report "    空闲内存: $mem_free"
add_to_report "    可用内存: $mem_available"

if compare_float "$mem_used_percent" ">" "85"; then
    echo "${RED}    警告: 内存使用率超过85%${NC}"
    add_to_report "    ${RED}警告: 内存使用率超过85%${NC}"
fi

echo ""
echo "    内存占用TOP5进程:"
ps -eo %mem,rss,pid,user,comm --sort=-%mem | head -6 | awk 'NR==1 {print "      " $0} NR>1 {printf "      %.2f%%  %-6s %-6d %-8s %s\n", $1, $2"K", $3, $4, $5}'
add_to_report "    内存占用TOP5进程:"
ps -eo %mem,rss,pid,user,comm --sort=-%mem | head -6 >> $REPORT_FILE

# 4.3 磁盘性能分析
echo ""
echo "  磁盘性能分析..."
echo "    磁盘分区使用率:"
add_to_report "    磁盘分区使用率:"
df -h | grep -vE 'tmpfs|loop|udev|shm' | awk 'NR>1 {print $0}' | while read line; do
    echo "    $line"
    add_to_report "    $line"
    usage=$(echo $line | awk '{print $5}' | sed 's/%//')
    filesystem=$(echo $line | awk '{print $6}')
    if [ "$usage" -gt 85 ] 2>/dev/null; then
        echo "${RED}    警告: $filesystem 分区使用率超过85%${NC}"
        add_to_report "    ${RED}警告: $filesystem 分区使用率超过85%${NC}"
    fi
done

echo ""
echo "    磁盘I/O性能(5秒采样):"
add_to_report "    磁盘I/O性能(5秒采样):"

# 兼容不同系统的iostat输出格式
if command -v iostat >/dev/null 2>&1; then
    iostat -x 1 2 2>/dev/null | awk '
    /^Device:/ { header_found=1; next }
    header_found && /^[a-zA-Z]/ && NF>=10 {
        printf "      %-8s  读速: %-8.1fKB/s  写速: %-8.1fKB/s  利用率: %s%%\n", $1, $6, $7, $(NF-1)
    }' 2>/dev/null
    
    iostat -x 1 2 2>/dev/null | awk '
    /^Device:/ { header_found=1; next }
    header_found && /^[a-zA-Z]/ && NF>=10' >> $REPORT_FILE 2>/dev/null
else
    echo "      iostat命令不可用，跳过磁盘I/O性能检测"
    add_to_report "      iostat命令不可用，跳过磁盘I/O性能检测"
fi

# 4.4 网络性能分析
echo ""
echo "  网络性能分析..."
echo "    网络接口流量(5秒采样):"
add_to_report "    网络接口流量(5秒采样):"

# 兼容不同系统的sar输出格式
if command -v sar >/dev/null 2>&1; then
    sar -n DEV 1 2 2>/dev/null | awk '
    /IFACE/ { next }
    /lo/ { next }
    /Average:/ && NF>=8 && ($6+$7>0) {
        printf "      %-8s  接收: %-8.2fKB/s  发送: %-8.2fKB/s  总流量: %-8.2fKB/s\n", $2, $6, $7, $6+$7
    }' 2>/dev/null
    
    sar -n DEV 1 2 2>/dev/null | awk '/Average:/ && NF>=8' >> $REPORT_FILE 2>/dev/null
else
    echo "      sar命令不可用，使用替代方法检测网络接口"
    # 使用/proc/net/dev作为替代方案
    for iface in $(ls /sys/class/net/ | grep -v lo); do
        rx_bytes=$(cat /proc/net/dev | grep "$iface:" | awk '{print $2}')
        tx_bytes=$(cat /proc/net/dev | grep "$iface:" | awk '{print $10}')
        if [ -n "$rx_bytes" ] && [ -n "$tx_bytes" ]; then
            echo "      $iface  接收: ${rx_bytes}B  发送: ${tx_bytes}B"
        fi
    done
fi

echo ""
echo "    网络连接状态分布:"
add_to_report "    网络连接状态分布:"

# 兼容不同系统的netstat命令
if command -v netstat >/dev/null 2>&1; then
    netstat -ant 2>/dev/null | awk '/^tcp/ {++S[$NF]} END {for(a in S) print "      " a ": " S[a] " 个连接"}'
    netstat -ant 2>/dev/null | awk '/^tcp/ {++S[$NF]} END {for(a in S) print "      " a ": " S[a] " 个连接"}' >> $REPORT_FILE
elif command -v ss >/dev/null 2>&1; then
    echo "      使用ss命令检测网络连接:"
    ss -ant 2>/dev/null | awk 'NR>1 && /^tcp/ {++S[$1]} END {for(a in S) print "      " a ": " S[a] " 个连接"}'
else
    echo "      netstat和ss命令都不可用，无法检测网络连接状态"
fi

# 5. 系统安全检测
echo ""
echo "${BLUE}5. 系统安全检测${NC}"
echo ""
add_to_report ""
add_to_report "5. 系统安全检测"

# 5.1 用户安全检查
echo "  用户安全检查..."
empty_passwords=$(awk -F: '($2 == "" && $1 != "root") {print $1}' /etc/shadow)
if [ -z "$empty_passwords" ]; then
    echo "${GREEN}    未发现空密码账户${NC}"
    add_to_report "    ${GREEN}未发现空密码账户${NC}"
else
    echo "${RED}    发现以下空密码账户: $empty_passwords${NC}"
    add_to_report "    ${RED}发现以下空密码账户: $empty_passwords${NC}"
fi

privileged_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [ -z "$privileged_users" ]; then
    echo "${GREEN}    未发现除root外的特权用户${NC}"
    add_to_report "    ${GREEN}未发现除root外的特权用户${NC}"
else
    echo "${RED}    发现以下非root特权用户: $privileged_users${NC}"
    add_to_report "    ${RED}发现以下非root特权用户: $privileged_users${NC}"
fi

# 5.2 关键文件权限检查
echo ""
echo "  关键文件权限检查..."
critical_files="/etc/passwd /etc/shadow /etc/sudoers /etc/group /etc/hosts /etc/resolv.conf"

for file in $critical_files; do
    if [ -f "$file" ]; then
        perms=$(stat -c "%a" "$file")
        case $file in
            "/etc/shadow")
                if [ "$perms" -ne 400 ]; then
                    echo "${RED}    不安全的权限: $file 权限为 $perms (应设置为400)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (应设置为400)${NC}"
                else
                    echo "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
            "/etc/sudoers")
                if [ "$perms" -ne 440 ]; then
                    echo "${RED}    不安全的权限: $file 权限为 $perms (应设置为440)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (应设置为440)${NC}"
                else
                    echo "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
            *)
                if [ "$perms" -gt 644 ]; then
                    echo "${RED}    不安全的权限: $file 权限为 $perms (建议不高于644)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (建议不高于644)${NC}"
                else
                    echo "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
        esac
    else
        echo "${YELLOW}    警告: 未找到文件 $file${NC}"
        add_to_report "    ${YELLOW}警告: 未找到文件 $file${NC}"
    fi
done

# 5.3 SSH与防火墙检查
echo ""
echo "  远程访问与防火墙检查..."
ssh_config="/etc/ssh/sshd_config"
if [ -f "$ssh_config" ]; then
    root_login=$(grep -E '^PermitRootLogin' $ssh_config | awk '{print $2}')
    if [ "$root_login" = "no" ]; then
        echo "${GREEN}    SSH已禁用root直接登录${NC}"
        add_to_report "    ${GREEN}SSH已禁用root直接登录${NC}"
    else
        echo "${RED}    SSH允许root直接登录 (建议设置为PermitRootLogin no)${NC}"
        add_to_report "    ${RED}SSH允许root直接登录 (建议设置为PermitRootLogin no)${NC}"
    fi
fi

if command -v ufw >/dev/null 2>&1; then
    ufw_status=$(ufw status | grep "Status" | awk '{print $2}')
    if [ "$ufw_status" = "active" ]; then
        echo "${GREEN}    UFW防火墙已激活${NC}"
        add_to_report "    ${GREEN}UFW防火墙已激活${NC}"
    else
        echo "${RED}    UFW防火墙未激活${NC}"
        add_to_report "    ${RED}UFW防火墙未激活${NC}"
    fi
elif command -v firewalld >/dev/null 2>&1; then
    firewalld_status=$(systemctl is-active firewalld)
    if [ "$firewalld_status" = "active" ]; then
        echo "${GREEN}    firewalld防火墙已激活${NC}"
        add_to_report "    ${GREEN}firewalld防火墙已激活${NC}"
    else
        echo "${RED}    firewalld防火墙未激活${NC}"
        add_to_report "    ${RED}firewalld防火墙未激活${NC}"
    fi
fi

# 6. 服务与系统更新检查
echo ""
echo "${BLUE}6. 服务状态与系统更新${NC}"
echo ""
add_to_report ""
add_to_report "6. 服务状态与系统更新"

# 6.1 关键服务状态
critical_services="sshd firewalld crond rsyslog docker nginx mysql redis"

echo "  关键服务状态检查..."
for service in $critical_services; do
    if systemctl is-active --quiet $service; then
        echo "${GREEN}    服务正常运行: $service${NC}"
        add_to_report "    ${GREEN}服务正常运行: $service${NC}"
    else
        if systemctl list-unit-files --type=service | grep -q "$service"; then
            echo "${RED}    服务已安装但未运行: $service${NC}"
            add_to_report "    ${RED}服务已安装但未运行: $service${NC}"
        else
            echo "${YELLOW}    服务未安装: $service${NC}"
            add_to_report "    ${YELLOW}服务未安装: $service${NC}"
        fi
    fi
done

# 6.2 系统更新检查
echo ""
echo "  系统更新检查..."

# 根据系统类型检查更新
OS=$(detect_os)
case $OS in
    ubuntu|debian)
        if command -v apt >/dev/null 2>&1; then
            apt list --upgradable 2>/dev/null | grep -v "WARNING" > /tmp/apt_updates.tmp
            updates=$(cat /tmp/apt_updates.tmp | wc -l)
            security_updates=$(grep -i security /tmp/apt_updates.tmp | wc -l)
            echo "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
            add_to_report "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
            rm -f /tmp/apt_updates.tmp
        fi
        ;;
    centos|rhel)
        if command -v yum >/dev/null 2>&1; then
            yum check-update 2>/dev/null > /tmp/yum_updates.tmp
            updates=$(grep -v "^$" /tmp/yum_updates.tmp | grep -v "Loaded plugins" | grep -v "Last metadata" | wc -l)
            yum check-update --security 2>/dev/null > /tmp/yum_security.tmp
            security_updates=$(grep -v "^$" /tmp/yum_security.tmp | grep -v "Loaded plugins" | grep -v "Last metadata" | wc -l)
            echo "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
            add_to_report "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
            rm -f /tmp/yum_updates.tmp /tmp/yum_security.tmp
        fi
        ;;
    fedora)
        if command -v dnf >/dev/null 2>&1; then
            dnf check-update 2>/dev/null > /tmp/dnf_updates.tmp
            updates=$(grep -v "^$" /tmp/dnf_updates.tmp | wc -l)
            echo "    可用系统更新: $updates 个"
            add_to_report "    可用系统更新: $updates 个"
            rm -f /tmp/dnf_updates.tmp
        fi
        ;;
    *)
        echo "    未能识别系统类型，跳过更新检查"
        add_to_report "    未能识别系统类型，跳过更新检查"
        ;;
esac

# 7. 日志与定时任务检查
echo ""
echo "${BLUE}7. 日志与定时任务检查${NC}"
echo ""
add_to_report ""
add_to_report "7. 日志与定时任务检查"

# 7.1 错误日志检查
echo "  系统错误日志检查..."

# 根据系统类型检查不同的日志文件
log_files=""
if [ -f /var/log/messages ]; then
    log_files="$log_files /var/log/messages"
fi
if [ -f /var/log/syslog ]; then
    log_files="$log_files /var/log/syslog"
fi
if [ -f /var/log/system.log ]; then
    log_files="$log_files /var/log/system.log"
fi

if [ -n "$log_files" ]; then
    error_logs=$(grep -iE "error|fail|critical|alert|emergency" $log_files 2>/dev/null | grep -v "CRON" | tail -10)
    if [ -n "$error_logs" ]; then
        echo "${YELLOW}    发现错误日志记录:${NC}"
        echo "$error_logs" | while read line; do
            echo "      $line"
            add_to_report "      $line"
        done
    else
        echo "${GREEN}    未发现明显错误日志${NC}"
        add_to_report "    ${GREEN}未发现明显错误日志${NC}"
    fi
else
    echo "${YELLOW}    未找到系统日志文件${NC}"
    add_to_report "    ${YELLOW}未找到系统日志文件${NC}"
fi

# 7.2 登录失败检查
echo ""
echo "  登录失败记录检查..."

# 根据系统类型检查不同的日志文件
auth_log_files=""
if [ -f /var/log/secure ]; then
    auth_log_files="$auth_log_files /var/log/secure"
fi
if [ -f /var/log/auth.log ]; then
    auth_log_files="$auth_log_files /var/log/auth.log"
fi
if [ -f /var/log/authorization.log ]; then
    auth_log_files="$auth_log_files /var/log/authorization.log"
fi

if [ -n "$auth_log_files" ]; then
    failed_logins=$(grep "Failed password" $auth_log_files 2>/dev/null | tail -5)
    if [ -n "$failed_logins" ]; then
        echo "${YELLOW}    发现登录失败记录:${NC}"
        echo "$failed_logins" | while read line; do
            echo "      $line"
            add_to_report "      $line"
        done
    else
        echo "${GREEN}    未发现登录失败记录${NC}"
        add_to_report "    ${GREEN}未发现登录失败记录${NC}"
    fi
else
    echo "${YELLOW}    未找到认证日志文件${NC}"
    add_to_report "    ${YELLOW}未找到认证日志文件${NC}"
fi

# 7.3 定时任务检查
echo ""
echo "  定时任务安全检查..."
suspicious_crons=$(grep -r -E 'wget|curl|bash -i|nc |netcat' /etc/cron* 2>/dev/null | grep -v -E '#|/usr/bin/')
if [ -n "$suspicious_crons" ]; then
    echo "${YELLOW}    发现可能存在风险的定时任务:${NC}"
    echo "$suspicious_crons" | while read line; do
        echo "      $line"
        add_to_report "      $line"
    done
else
    echo "${GREEN}    未发现明显风险的系统级定时任务${NC}"
    add_to_report "    ${GREEN}未发现明显风险的系统级定时任务${NC}"
fi

# 巡检总结
echo ""
echo "${YELLOW}===== 系统综合巡检完成 ====="
echo "巡检报告已保存至: $REPORT_FILE"
echo "重点关注项:"
if compare_float "$usage_rate" ">" "80"; then echo "  - 系统句柄使用率过高"; fi
if compare_float "$cpu_usage" ">" "80"; then echo "  - CPU使用率过高"; fi
if compare_float "$mem_used_percent" ">" "85"; then echo "  - 内存使用率过高"; fi
if [ -n "$empty_passwords" ] || [ -n "$privileged_users" ]; then echo "  - 用户安全配置存在问题"; fi
echo "=========================${NC}"

echo ""
add_to_report "===== 巡检总结 ====="
add_to_report "检查完成时间: $(date)"
add_to_report "重点关注项:"
if compare_float "$usage_rate" ">" "80"; then add_to_report "  - 系统句柄使用率过高"; fi
if compare_float "$cpu_usage" ">" "80"; then add_to_report "  - CPU使用率过高"; fi
if compare_float "$mem_used_percent" ">" "85"; then add_to_report "  - 内存使用率过高"; fi
if [ -n "$empty_passwords" ] || [ -n "$privileged_users" ]; then add_to_report "  - 用户安全配置存在问题"; fi