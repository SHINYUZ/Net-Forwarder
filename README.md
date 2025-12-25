# 🚀 Net Forwarder - VPS 流量转发全能脚本

![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Bash-blue) ![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

一个轻量、美观且功能强大的 Linux 流量转发管理脚本。集成 **realm** (Go语言开发，高效) 与 **iptables** (系统原生) 两种转发方式，支持 TCP/UDP 协议，支持域名解析转发。

---

## ✨ 功能特性

- **双核驱动**：
  - **realm**：基于 Go 语言，资源占用低，转发效率高，支持域名解析。
  - **iptables**：基于 Linux 内核 Netfilter，系统原生支持，极其稳定。
- **贴心功能**：
  - **支持规则备注**：添加规则时可输入备注，管理更清晰。
  - **智能配置**：内置 realm 最佳网络与 DNS 优化配置。
- **极致体验**：
  - 精心打磨的 CLI 交互界面，像素级对齐，清爽易读。
  - 拥有详细的运行状态检测（running/stopped）。
- **简单易用**：
  - 全菜单式操作，告别复杂的配置文件和命令行。
  - 支持 **快捷指令 `zf`**，随时唤出管理面板。
- **自动化管理**：
  - 自动配置 Systemd 服务，完美支持**开机自启**。
  - 智能判断系统架构 (x86_64/aarch64) 进行安装。
- **协议支持**：
  - 支持 TCP、UDP 以及 TCP+UDP 双协议同时转发。
  - 支持 **IPv4 / 域名** 作为目标地址。

---

## 🛠 环境要求

- **操作系统**：CentOS 7+ / Debian 10+ / Ubuntu 20+
- **架构**：x86_64 / aarch64 (ARM64)
- **权限**：Root 用户

---

## 📥 一键安装 / 更新

复制以下命令并在 VPS 终端中执行：

```bash
wget -N --no-check-certificate [https://raw.githubusercontent.com/Shinyuz/net-forwarder/main/forwarding.sh](https://raw.githubusercontent.com/Shinyuz/net-forwarder/main/forwarding.sh) && chmod +x forwarding.sh && ./forwarding.sh
```
(如果下载失败，请检查 VPS 的网络连接或 DNS 设置)

## 📖 使用指南

安装完成后，你可以通过以下命令随时打开管理菜单：

```bash
zf
```

## 📂 目录结构说明

| 组件 | 路径 | 说明 |
| :--- | :--- | :--- |
| **realm 主程序** | `/usr/local/bin/realm` | 二进制执行文件 |
| **realm 配置文件** | `/etc/realm/config.toml` | 存储转发规则 |
| **realm 备注文件** | `/etc/realm/remarks.txt` | 存储规则备注信息 |
| **realm 服务** | `/etc/systemd/system/realm.service` | Systemd 守护进程 |
| **iptables v4 规则 (Debian)** | `/etc/iptables/rules.v4` | IPv4 规则持久化文件 |
| **iptables v6 规则 (Debian)** | `/etc/iptables/rules.v6` | IPv6 规则持久化文件 |
| **iptables v4 规则 (CentOS)** | `/etc/sysconfig/iptables` | IPv4 规则持久化文件 |
| **iptables v6 规则 (CentOS)** | `/etc/sysconfig/ip6tables` | IPv6 规则持久化文件 |
| **脚本快捷方式** | `/usr/bin/zf` | 快捷启动指令 |

## ⚠️ 免责声明

1. 本脚本仅供学习交流使用，请勿用于非法用途。
2. 使用本脚本造成的任何损失（包括但不限于数据丢失、服务器被封锁等），作者不承担任何责任。
3. 请遵守当地法律法规。
