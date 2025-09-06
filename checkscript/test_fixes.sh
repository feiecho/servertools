#!/bin/bash

# CentOS 7格式问题修复验证脚本
echo "测试CentOS 7格式修复效果..."

# 测试颜色输出
echo "测试颜色输出:"
if [ -t 1 ] && [ "$TERM" != "dumb" ]; then
    # 使用tput优先，ANSI转义序列备选
    if command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
        RED=$(tput setaf 1)
        GREEN=$(tput setaf 2)
        YELLOW=$(tput setaf 3)
        BLUE=$(tput setaf 4)
        NC=$(tput sgr0)
        echo "${GREEN}✓ 使用tput颜色设置${NC}"
    else
        RED=$'\e[31m'
        GREEN=$'\e[32m'
        YELLOW=$'\e[33m'
        BLUE=$'\e[34m'
        NC=$'\e[0m'
        echo "${GREEN}✓ 使用ANSI转义序列${NC}"
    fi
else
    echo "✓ 检测到非交互终端，禁用颜色"
fi

# 测试文件权限检查
echo ""
echo "测试文件权限检查:"
if [ -f "/etc/shadow" ]; then
    perms=$(stat -c "%a" "/etc/shadow")
    echo "/etc/shadow 权限: $perms"
    if [ "$perms" -eq 400 ] || [ "$perms" -eq 0 ]; then
        echo "✓ /etc/shadow 权限检测正常"
    else
        echo "✗ /etc/shadow 权限异常: $perms"
    fi
fi

# 测试PATH环境变量分析
echo ""
echo "测试PATH环境变量分析:"
path_var=$PATH
path_count=$(echo "$path_var" | tr ':' '\n' | wc -l)
echo "PATH包含 $path_count 个路径"

# 测试进程句柄分析
echo ""
echo "测试进程句柄分析:"
if [ -d "/proc/1/fd" ]; then
    echo "✓ /proc文件系统可用"
    fd_count=$(ls "/proc/1/fd" 2>/dev/null | wc -l)
    echo "PID 1 的句柄数: $fd_count"
else
    echo "✗ /proc文件系统不可用"
fi

# 测试网络接口检测
echo ""
echo "测试网络接口检测:"
if [ -f "/proc/net/dev" ]; then
    echo "✓ /proc/net/dev 文件存在"
    interfaces=$(ls /sys/class/net/ | grep -v lo)
    for iface in $interfaces; do
        rx_bytes=$(cat /proc/net/dev | grep "$iface:" | awk '{print $2}')
        if [ -n "$rx_bytes" ]; then
            echo "接口 $iface 接收字节: $rx_bytes"
        fi
    done
else
    echo "✗ /proc/net/dev 文件不存在"
fi

echo ""
echo "测试完成！"