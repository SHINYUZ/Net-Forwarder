# 🚀 Net Forwarder - VPS 流量转发全能脚本

![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Bash-blue) ![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

一个轻量、美观且功能强大的 Linux 流量转发管理脚本。集成 **Realm** (Go语言开发，高效) 与 **iptables** (系统原生) 两种转发方式，支持 TCP/UDP 协议，支持域名解析转发。

---

## ✨ 功能特性

- **双核驱动**：
  - **Realm**：基于 Go 语言，资源占用低，转发效率高，支持域名解析。
  - **iptables**：基于 Linux 内核 Netfilter，系统原生支持，极其稳定。
- **极致体验**：
  - 精心打磨的 CLI 交互界面，像素级对齐，清爽易读。
  - 拥有详细的运行状态检测（Running/Stopped）。
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