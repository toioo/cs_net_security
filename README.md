# 🛡️ Network Intrusion Detection and Port Scan Alarm System

本项目是一个基于 **Python + Scapy** 实现的轻量级实时网络入侵检测系统，能够在局域网环境中检测典型的 **端口扫描行为**（如 Nmap -sS 扫描），并在超出访问阈值时发出告警。

---

## ✨ 项目功能简介

### 📡 2.1 网络流量监控模块

- 使用 [**Scapy**](https://scapy.readthedocs.io/) 捕获网络数据包；
- 实时监听指定网卡接口（如 `eth0`）；
- 提取源 IP、目标端口、TCP Flags 等关键信息。

### 🛡️ 2.2 异常检测算法模块

- 采用 **基于阈值的检测方法**；
- 统计每个 IP 在单位时间内访问的目标端口数量；
- 若访问速率超过设定阈值（如 20 个端口/秒），即触发“端口扫描警报”；
- 可检测如 Nmap 等工具发起的探测攻击。

---

## 📦 环境依赖

- Python 3.x
- [Scapy](https://scapy.readthedocs.io/) 抓包库
- sudo 权限（Linux/WSL2 下抓包需要 root 权限）

---

## 🚀 使用步骤（ WSL2 ）

### 查看wsl2 ip
```
ip addr show eth0 | grep inet
```
如 **172.22.0.1**
###  安装 Scapy

```
pip install scapy
```

###  运行监听脚本
```
sudo python run.py 
```
- 默认监听接口为 eth0；

### 使用 Nmap 进行测试（扫描两次以上）
在 Windows 主机上打开终端（CMD/PowerShell）运行：
```
nmap -sS -T4 <WSL2_IP> 
```
✅ WSL2_IP是刚刚ip addr的结果
✅ 第一次扫描可能未触发警报（因未超过端口访问阈值）
✅ 后续重复扫描将触发如下告警：

```
[!!!] Port scan detected from 172.22.0.1 (42.00 ports/sec)
[ALERT] Detected nmap_stealth_scan from 172.22.0.1
```
