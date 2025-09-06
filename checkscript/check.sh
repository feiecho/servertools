#!/bin/bash
# 综合系统巡检工具
# 功能整合：安全检测、性能监控、环境变量检查、句柄分析、服务状态监控等
# 使用前请以root权限运行，建议定期执行（如每日/每周）

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 检查是否以root权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：此脚本需要以root权限运行，请使用sudo或切换到root用户${NC}"
    exit 1
fi

# 检查必要工具是否安装
check_dependencies() {
    dependencies="sysstat iotop net-tools"
    missing=""

    for dep in $dependencies; do
        if ! command -v $dep >/dev/null 2>&1 && ! dpkg -s $dep >/dev/null 2>&1 && ! rpm -q $dep >/dev/null 2>&1; then
            missing="$missing $dep"
        fi
    done

    if [ -n "$missing" ]; then
        echo -e "${YELLOW}检测到缺少必要工具，正在尝试安装...${NC}"
        if command -v apt >/dev/null 2>&1; then
            sudo apt update -y >/dev/null 2>&1
            sudo apt install -y $missing >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y $missing >/dev/null 2>&1
        else
            echo -e "${RED}无法自动安装依赖，请手动安装: $missing${NC}"
            exit 1
        fi
    fi
}

# 初始化巡检报告
REPORT_FILE="system_inspection_$(date +%Y%m%d_%H%M%S).log"
echo -e "系统综合巡检报告 - $(date)\n" > $REPORT_FILE

# 添加内容到报告
add_to_report() {
    echo -e "$1" >> $REPORT_FILE
}

# 显示开始信息
echo -e "${YELLOW}===== 系统综合巡检工具 ====="
echo "巡检时间: $(date)"
echo "报告将保存至: $REPORT_FILE"
echo "正在检查依赖工具..."
check_dependencies
echo "=================================${NC}"

# 1. 系统基本信息
echo -e "\n${BLUE}1. 系统基本信息${NC}"
add_to_report "1. 系统基本信息"

os_info=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
kernel_version=$(uname -r)
hostname=$(hostname)
uptime=$(uptime | awk '{print $3 " " $4}' | sed 's/,//')
ip_address=$(hostname -I | awk '{print $1}')

echo -e "  系统版本: $os_info"
echo -e "  内核版本: $kernel_version"
echo -e "  主机名: $hostname"
echo -e "  IP地址: $ip_address"
echo -e "  运行时间: $uptime"
add_to_report "  系统版本: $os_info"
add_to_report "  内核版本: $kernel_version"
add_to_report "  主机名: $hostname"
add_to_report "  IP地址: $ip_address"
add_to_report "  运行时间: $uptime"

# 2. 环境变量安全检测
echo -e "\n${BLUE}2. 环境变量安全检测${NC}"
add_to_report "\n2. 环境变量安全检测"

# 2.1 PATH环境变量分析
echo -e "  PATH环境变量分析..."
path_var=$PATH
# 使用兼容的方式处理PATH分析
path_count=$(echo "$path_var" | tr ':' '\n' | wc -l)
echo "    PATH包含 $path_count 个路径"
add_to_report "    PATH包含 $path_count 个路径"

dangerous_paths="/ /root /tmp /var/tmp /dev/shm"
echo "$path_var" | tr ':' '\n' | while read -r path; do
    for danger in $dangerous_paths; do
        if [ "$path" = "$danger" ]; then
            echo -e "${RED}    危险路径: $path (包含在PATH中)${NC}"
            add_to_report "    ${RED}危险路径: $path (包含在PATH中)${NC}"
        fi
    done

    if [ -d "$path" ] && [ -w "$path" ] && ! ls -ld "$path" | grep -qE '^drwxr-xr-x'; then
        echo -e "${YELLOW}    可写路径: $path (存在非授权写入风险)${NC}"
        add_to_report "    ${YELLOW}可写路径: $path (存在非授权写入风险)${NC}"
    fi
done

# 2.2 敏感环境变量扫描
echo -e "\n  敏感环境变量扫描..."
sensitive_vars="PASSWORD SECRET KEY TOKEN CREDENTIAL PASS DB_PASS"
found_sensitive=0
for var in $sensitive_vars; do
    matches=$(env | grep -i "$var" | grep -v -E '^SHLVL=|^PWD=|^_=|^LS_COLORS=')
    if [ -n "$matches" ]; then
        found_sensitive=1
        echo -e "${YELLOW}    潜在敏感变量:${NC}"
        echo "$matches" | awk -F= '{print "      " $1 "=***(内容已隐藏)***"}'
        add_to_report "    ${YELLOW}潜在敏感变量: $var${NC}"
    fi
done
if [ $found_sensitive -eq 0 ]; then
    echo -e "${GREEN}    未发现明显敏感环境变量${NC}"
    add_to_report "    ${GREEN}未发现明显敏感环境变量${NC}"
fi

# 2.3 环境配置文件检查
echo -e "\n  环境配置文件权限检查..."
env_files="/etc/profile /etc/bashrc ~/.bashrc ~/.bash_profile"
for file in $env_files; do
    expanded_file=$(eval echo "$file")
    if [ -f "$expanded_file" ]; then
        perms=$(stat -c "%a" "$expanded_file")
        if [ "$perms" -gt 644 ]; then
            echo -e "${RED}    不安全权限: $expanded_file (权限$perms，建议≤644)${NC}"
            add_to_report "    ${RED}不安全权限: $expanded_file (权限$perms，建议≤644)${NC}"
        else
            echo -e "    安全权限: $expanded_file (权限$perms)"
            add_to_report "    安全权限: $expanded_file (权限$perms)"
        fi
    fi
done

# 3. 系统句柄数分析
echo -e "\n${BLUE}3. 系统句柄数分析${NC}"
add_to_report "\n3. 系统句柄数分析"

# 3.1 句柄限制配置
echo -e "  句柄限制配置..."
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

usage_rate=$(echo "scale=2; $sys_current_max / $sys_max_open * 100" | bc)
echo "    系统句柄整体使用率: $usage_rate%"
add_to_report "    系统句柄整体使用率: $usage_rate%"

if [ $(echo "$usage_rate > 80" | bc) -eq 1 ]; then
    echo -e "${RED}    警告: 系统句柄使用率超过80%，可能面临耗尽风险${NC}"
    add_to_report "    ${RED}警告: 系统句柄使用率超过80%，可能面临耗尽风险${NC}"
fi

# 3.2 进程句柄TOP分析
echo -e "\n  句柄使用TOP 10进程..."
echo "    排名  PID    句柄数  进程名"
echo "    -------------------------"
add_to_report "    进程句柄使用TOP 10:"
add_to_report "    排名  PID    句柄数  进程名"
add_to_report "    -------------------------"

rank=0
lsof -n | awk '{print $2}' | sort | uniq -c | sort -nr | head -10 | awk '{print $1, $2}' | while read count pid; do
    if [ -n "$pid" ] && [ "$pid" -gt 0 ]; then
        cmd=$(ps -p $pid -o comm= 2>/dev/null)
        rank=$(expr $rank + 1)
        printf "    %-5d %-6d %-7d %s\n" $rank $pid $count "$cmd"
        add_to_report "    $rank    $pid    $count    $cmd"
    fi
done

# 4. 系统性能深度检测
echo -e "\n${BLUE}4. 系统性能检测${NC}"
add_to_report "\n4. 系统性能检测"

# 4.1 CPU性能分析
echo -e "  CPU性能分析..."
cpu_cores=$(grep -c ^processor /proc/cpuinfo)
cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed -e 's/^ *//')

echo "    CPU型号: $cpu_model"
echo "    CPU核心数: $cpu_cores"
add_to_report "    CPU型号: $cpu_model"
add_to_report "    CPU核心数: $cpu_cores"

cpu_usage=$(mpstat 5 1 | awk '/Average/ {printf "%.2f", 100 - $13}')
echo "    CPU平均使用率(5秒): $cpu_usage%"
add_to_report "    CPU平均使用率(5秒): $cpu_usage%"

if [ $(echo "$cpu_usage > 80" | bc) -eq 1 ]; then
    echo -e "${RED}    警告: CPU使用率超过80%${NC}"
    add_to_report "    ${RED}警告: CPU使用率超过80%${NC}"
fi

echo -e "\n    CPU占用TOP5进程:"
ps -eo %cpu,pid,user,comm --sort=-%cpu | head -6 | awk 'NR==1 {print "      " $0} NR>1 {printf "      %.2f%%  %-6d %-8s %s\n", $1, $2, $3, $4}'
add_to_report "    CPU占用TOP5进程:"
ps -eo %cpu,pid,user,comm --sort=-%cpu | head -6 >> $REPORT_FILE

# 4.2 内存性能分析
echo -e "\n  内存性能分析..."
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

if [ $(echo "$mem_used_percent > 85" | bc) -eq 1 ]; then
    echo -e "${RED}    警告: 内存使用率超过85%${NC}"
    add_to_report "    ${RED}警告: 内存使用率超过85%${NC}"
fi

echo -e "\n    内存占用TOP5进程:"
ps -eo %mem,rss,pid,user,comm --sort=-%mem | head -6 | awk 'NR==1 {print "      " $0} NR>1 {printf "      %.2f%%  %-6s %-6d %-8s %s\n", $1, $2"K", $3, $4, $5}'
add_to_report "    内存占用TOP5进程:"
ps -eo %mem,rss,pid,user,comm --sort=-%mem | head -6 >> $REPORT_FILE

# 4.3 磁盘性能分析
echo -e "\n  磁盘性能分析..."
echo "    磁盘分区使用率:"
add_to_report "    磁盘分区使用率:"
df -h | grep -vE 'tmpfs|loop|udev' | awk 'NR>1 {print $0}' | while read line; do
    echo "    $line"
    add_to_report "    $line"
    usage=$(echo $line | awk '{print $5}' | sed 's/%//')
    if [ $usage -gt 85 ]; then
        echo -e "${RED}    警告: $(echo $line | awk '{print $6}') 分区使用率超过85%${NC}"
        add_to_report "    ${RED}警告: $(echo $line | awk '{print $6}') 分区使用率超过85%${NC}"
    fi
done

echo -e "\n    磁盘I/O性能(5秒采样):"
iostat -x 5 1 | awk 'NR>3 {printf "      %-8s  读速: %-6sB/s  写速: %-6sB/s  利用率: %s\n", $1, $6*512, $7*512, $14 "%"}'
add_to_report "    磁盘I/O性能(5秒采样):"
iostat -x 5 1 | awk 'NR>3' >> $REPORT_FILE

# 4.4 网络性能分析
echo -e "\n  网络性能分析..."
echo "    网络接口流量(5秒采样):"
sar -n DEV 5 1 | awk 'NR>2 {if($6+$7>0) printf "      %-6s  接收: %-6sB/s  发送: %-6sB/s  总流量: %-6sB/s\n", $2, $6, $7, $6+$7}'
add_to_report "    网络接口流量(5秒采样):"
sar -n DEV 5 1 | awk 'NR>2' >> $REPORT_FILE

echo -e "\n    网络连接状态分布:"
netstat -ant | awk '/^tcp/ {++S[$NF]} END {for(a in S) print "      " a ": " S[a] " 个连接"}'
add_to_report "    网络连接状态分布:"
netstat -ant | awk '/^tcp/ {++S[$NF]} END {for(a in S) print "      " a ": " S[a] " 个连接"}' >> $REPORT_FILE

# 5. 系统安全检测
echo -e "\n${BLUE}5. 系统安全检测${NC}"
add_to_report "\n5. 系统安全检测"

# 5.1 用户安全检查
echo -e "  用户安全检查..."
empty_passwords=$(awk -F: '($2 == "" && $1 != "root") {print $1}' /etc/shadow)
if [ -z "$empty_passwords" ]; then
    echo -e "${GREEN}    未发现空密码账户${NC}"
    add_to_report "    ${GREEN}未发现空密码账户${NC}"
else
    echo -e "${RED}    发现以下空密码账户: $empty_passwords${NC}"
    add_to_report "    ${RED}发现以下空密码账户: $empty_passwords${NC}"
fi

privileged_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [ -z "$privileged_users" ]; then
    echo -e "${GREEN}    未发现除root外的特权用户${NC}"
    add_to_report "    ${GREEN}未发现除root外的特权用户${NC}"
else
    echo -e "${RED}    发现以下非root特权用户: $privileged_users${NC}"
    add_to_report "    ${RED}发现以下非root特权用户: $privileged_users${NC}"
fi

# 5.2 关键文件权限检查
echo -e "\n  关键文件权限检查..."
critical_files="/etc/passwd /etc/shadow /etc/sudoers /etc/group /etc/hosts /etc/resolv.conf"

for file in $critical_files; do
    if [ -f "$file" ]; then
        perms=$(stat -c "%a" "$file")
        case $file in
            "/etc/shadow")
                if [ "$perms" -ne 400 ]; then
                    echo -e "${RED}    不安全的权限: $file 权限为 $perms (应设置为400)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (应设置为400)${NC}"
                else
                    echo -e "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
            "/etc/sudoers")
                if [ "$perms" -ne 440 ]; then
                    echo -e "${RED}    不安全的权限: $file 权限为 $perms (应设置为440)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (应设置为440)${NC}"
                else
                    echo -e "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
            *)
                if [ "$perms" -gt 644 ]; then
                    echo -e "${RED}    不安全的权限: $file 权限为 $perms (建议不高于644)${NC}"
                    add_to_report "    ${RED}不安全的权限: $file 权限为 $perms (建议不高于644)${NC}"
                else
                    echo -e "${GREEN}    安全的权限: $file 权限为 $perms${NC}"
                    add_to_report "    ${GREEN}安全的权限: $file 权限为 $perms${NC}"
                fi
                ;;
        esac
    else
        echo -e "${YELLOW}    警告: 未找到文件 $file${NC}"
        add_to_report "    ${YELLOW}警告: 未找到文件 $file${NC}"
    fi
done

# 5.3 SSH与防火墙检查
echo -e "\n  远程访问与防火墙检查..."
ssh_config="/etc/ssh/sshd_config"
if [ -f "$ssh_config" ]; then
    root_login=$(grep -E '^PermitRootLogin' $ssh_config | awk '{print $2}')
    if [ "$root_login" = "no" ]; then
        echo -e "${GREEN}    SSH已禁用root直接登录${NC}"
        add_to_report "    ${GREEN}SSH已禁用root直接登录${NC}"
    else
        echo -e "${RED}    SSH允许root直接登录 (建议设置为PermitRootLogin no)${NC}"
        add_to_report "    ${RED}SSH允许root直接登录 (建议设置为PermitRootLogin no)${NC}"
    fi
fi

if command -v ufw >/dev/null 2>&1; then
    ufw_status=$(ufw status | grep "Status" | awk '{print $2}')
    if [ "$ufw_status" = "active" ]; then
        echo -e "${GREEN}    UFW防火墙已激活${NC}"
        add_to_report "    ${GREEN}UFW防火墙已激活${NC}"
    else
        echo -e "${RED}    UFW防火墙未激活${NC}"
        add_to_report "    ${RED}UFW防火墙未激活${NC}"
    fi
elif command -v firewalld >/dev/null 2>&1; then
    firewalld_status=$(systemctl is-active firewalld)
    if [ "$firewalld_status" = "active" ]; then
        echo -e "${GREEN}    firewalld防火墙已激活${NC}"
        add_to_report "    ${GREEN}firewalld防火墙已激活${NC}"
    else
        echo -e "${RED}    firewalld防火墙未激活${NC}"
        add_to_report "    ${RED}firewalld防火墙未激活${NC}"
    fi
fi

# 6. 服务与系统更新检查
echo -e "\n${BLUE}6. 服务状态与系统更新${NC}"
add_to_report "\n6. 服务状态与系统更新"

# 6.1 关键服务状态
critical_services="sshd firewalld crond rsyslog docker nginx mysql redis"

echo -e "  关键服务状态检查..."
for service in $critical_services; do
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}    服务正常运行: $service${NC}"
        add_to_report "    ${GREEN}服务正常运行: $service${NC}"
    else
        if systemctl list-unit-files --type=service | grep -q "$service"; then
            echo -e "${RED}    服务已安装但未运行: $service${NC}"
            add_to_report "    ${RED}服务已安装但未运行: $service${NC}"
        else
            echo -e "${YELLOW}    服务未安装: $service${NC}"
            add_to_report "    ${YELLOW}服务未安装: $service${NC}"
        fi
    fi
done

# 6.2 系统更新检查
echo -e "\n  系统更新检查..."
if command -v apt >/dev/null 2>&1; then
    updates=$(apt list --upgradable 2>/dev/null | wc -l)
    security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
    echo -e "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
    add_to_report "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
elif command -v yum >/dev/null 2>&1; then
    updates=$(yum check-update 2>/dev/null | wc -l)
    security_updates=$(yum check-update --security 2>/dev/null | wc -l)
    echo -e "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
    add_to_report "    可用系统更新: $updates 个 (其中安全更新: $security_updates 个)"
fi

# 7. 日志与定时任务检查
echo -e "\n${BLUE}7. 日志与定时任务检查${NC}"
add_to_report "\n7. 日志与定时任务检查"

# 7.1 错误日志检查
echo -e "  系统错误日志检查..."
error_logs=$(grep -iE "error|fail|critical|alert|emergency" /var/log/messages /var/log/syslog 2>/dev/null | grep -v "CRON" | tail -10)
if [ -n "$error_logs" ]; then
    echo -e "${YELLOW}    发现错误日志记录:${NC}"
    echo "$error_logs" | while read line; do
        echo "      $line"
        add_to_report "      $line"
    done
else
    echo -e "${GREEN}    未发现明显错误日志${NC}"
    add_to_report "    ${GREEN}未发现明显错误日志${NC}"
fi

# 7.2 登录失败检查
echo -e "\n  登录失败记录检查..."
failed_logins=$(grep "Failed password" /var/log/secure /var/log/auth.log 2>/dev/null | tail -5)
if [ -n "$failed_logins" ]; then
    echo -e "${YELLOW}    发现登录失败记录:${NC}"
    echo "$failed_logins" | while read line; do
        echo "      $line"
        add_to_report "      $line"
    done
else
    echo -e "${GREEN}    未发现登录失败记录${NC}"
    add_to_report "    ${GREEN}未发现登录失败记录${NC}"
fi

# 7.3 定时任务检查
echo -e "\n  定时任务安全检查..."
suspicious_crons=$(grep -r -E 'wget|curl|bash -i|nc |netcat' /etc/cron* 2>/dev/null | grep -v -E '#|/usr/bin/')
if [ -n "$suspicious_crons" ]; then
    echo -e "${YELLOW}    发现可能存在风险的定时任务:${NC}"
    echo "$suspicious_crons" | while read line; do
        echo "      $line"
        add_to_report "      $line"
    done
else
    echo -e "${GREEN}    未发现明显风险的系统级定时任务${NC}"
    add_to_report "    ${GREEN}未发现明显风险的系统级定时任务${NC}"
fi

# 巡检总结
echo -e "\n${YELLOW}===== 系统综合巡检完成 ====="
echo "巡检报告已保存至: $REPORT_FILE"
echo "重点关注项:"
if (( $(echo "$usage_rate > 80" | bc -l) )); then echo "  - 系统句柄使用率过高"; fi
if (( $(echo "$cpu_usage > 80" | bc -l) )); then echo "  - CPU使用率过高"; fi
if (( $(echo "$mem_used_percent > 85" | bc -l) )); then echo "  - 内存使用率过高"; fi
if [ -n "$empty_passwords" ] || [ -n "$privileged_users" ]; then echo "  - 用户安全配置存在问题"; fi
echo "=========================${NC}"

add_to_report "\n===== 巡检总结 ====="
add_to_report "检查完成时间: $(date)"
add_to_report "重点关注项:"
if (( $(echo "$usage_rate > 80" | bc -l) )); then add_to_report "  - 系统句柄使用率过高"; fi
if (( $(echo "$cpu_usage > 80" | bc -l) )); then add_to_report "  - CPU使用率过高"; fi
if (( $(echo "$mem_used_percent > 85" | bc -l) )); then add_to_report "  - 内存使用率过高"; fi
if [ -n "$empty_passwords" ] || [ -n "$privileged_users" ]; then add_to_report "  - 用户安全配置存在问题"; fi