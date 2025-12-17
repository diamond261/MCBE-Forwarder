#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================
IP/端口转发脚本 - 游戏服务器转发工具
适用于: Minecraft基岩版(MCBE)等游戏
支持: TCP 和 UDP 协议
================================================

使用方法:
  客户端 -> 中转服务器(本机:54321) -> 目标服务器(IP:19132)
"""

import socket
import threading
import json
import logging
import sys
import time
import os
from typing import Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

# ==================== 配置类 ====================


@dataclass
class ForwardConfig:
    """转发配置"""

    listen_host: str = "0.0.0.0"
    listen_port: int = 54321
    target_host: str = "127.0.0.1"
    target_port: int = 19132
    enable_tcp: bool = True
    enable_udp: bool = True
    buffer_size: int = 65535
    udp_timeout: int = 120
    log_level: str = "INFO"

    @classmethod
    def from_dict(cls, data: dict) -> "ForwardConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> dict:
        return {
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "enable_tcp": self.enable_tcp,
            "enable_udp": self.enable_udp,
            "buffer_size": self.buffer_size,
            "udp_timeout": self.udp_timeout,
            "log_level": self.log_level,
        }


# ==================== 日志设置 ====================


def setup_logger(level: str = "INFO") -> logging.Logger:
    """设置日志"""
    logger = logging.getLogger("PortForwarder")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 清除已有的处理器
    logger.handlers.clear()

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # 格式化
    formatter = logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# ==================== TCP转发器 ====================


class TCPForwarder:
    """TCP端口转发器"""

    def __init__(self, config: ForwardConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.connections = 0
        self.lock = threading.Lock()

    def start(self):
        """启动TCP转发服务"""
        self.running = True

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)  # 设置超时以便能够优雅退出
            self.server_socket.bind((self.config.listen_host, self.config.listen_port))
            self.server_socket.listen(100)

            self.logger.info(
                f"[TCP] ✓ 监听启动 {self.config.listen_host}:{self.config.listen_port}"
            )

            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()

                    with self.lock:
                        self.connections += 1
                        conn_id = self.connections

                    self.logger.info(
                        f"[TCP] 新连接 #{conn_id} 来自 {client_addr[0]}:{client_addr[1]}"
                    )

                    # 创建处理线程
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, client_addr, conn_id),
                        daemon=True,
                    )
                    handler_thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"[TCP] 接受连接错误: {e}")

        except Exception as e:
            self.logger.error(f"[TCP] 启动失败: {e}")
        finally:
            self.stop()

    def _handle_connection(
        self, client_socket: socket.socket, client_addr: Tuple, conn_id: int
    ):
        """处理单个TCP连接"""
        target_socket = None

        try:
            # 连接到目标服务器
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(10)
            target_socket.connect((self.config.target_host, self.config.target_port))
            target_socket.settimeout(None)

            self.logger.info(f"[TCP] #{conn_id} 已连接到目标服务器")

            # 创建双向转发线程
            stop_event = threading.Event()

            t1 = threading.Thread(
                target=self._forward_data,
                args=(client_socket, target_socket, f"#{conn_id} C→S", stop_event),
                daemon=True,
            )
            t2 = threading.Thread(
                target=self._forward_data,
                args=(target_socket, client_socket, f"#{conn_id} S→C", stop_event),
                daemon=True,
            )

            t1.start()
            t2.start()

            # 等待任一方向结束
            t1.join()
            t2.join()

        except socket.timeout:
            self.logger.warning(f"[TCP] #{conn_id} 连接目标服务器超时")
        except ConnectionRefusedError:
            self.logger.warning(f"[TCP] #{conn_id} 目标服务器拒绝连接")
        except Exception as e:
            self.logger.error(f"[TCP] #{conn_id} 错误: {e}")
        finally:
            self._close_socket(client_socket)
            self._close_socket(target_socket)
            self.logger.info(f"[TCP] #{conn_id} 连接已关闭")

    def _forward_data(
        self,
        source: socket.socket,
        dest: socket.socket,
        direction: str,
        stop_event: threading.Event,
    ):
        """转发数据"""
        total_bytes = 0

        try:
            while self.running and not stop_event.is_set():
                try:
                    source.settimeout(1.0)
                    data = source.recv(self.config.buffer_size)

                    if not data:
                        break

                    dest.sendall(data)
                    total_bytes += len(data)

                except socket.timeout:
                    continue
                except Exception:
                    break

        finally:
            stop_event.set()
            self.logger.debug(f"[TCP] {direction} 传输完成, 共 {total_bytes} 字节")

    def _close_socket(self, sock: Optional[socket.socket]):
        """安全关闭socket"""
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            try:
                sock.close()
            except:
                pass

    def stop(self):
        """停止TCP转发服务"""
        self.running = False
        self._close_socket(self.server_socket)
        self.logger.info("[TCP] ✗ 服务已停止")


# ==================== UDP转发器 ====================


class UDPForwarder:
    """UDP端口转发器 - 适用于游戏"""

    def __init__(self, config: ForwardConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.running = False
        self.socket: Optional[socket.socket] = None

        # 客户端会话管理
        # key: 客户端地址(ip, port)
        # value: {'socket': socket, 'last_active': timestamp}
        self.sessions: Dict[Tuple[str, int], dict] = {}
        self.sessions_lock = threading.Lock()

        # 统计信息
        self.stats = {"packets_in": 0, "packets_out": 0, "bytes_in": 0, "bytes_out": 0}

    def start(self):
        """启动UDP转发服务"""
        self.running = True

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # 增大缓冲区（游戏需要）
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)

            self.socket.settimeout(1.0)
            self.socket.bind((self.config.listen_host, self.config.listen_port))

            self.logger.info(
                f"[UDP] ✓ 监听启动 {self.config.listen_host}:{self.config.listen_port}"
            )

            # 启动会话清理线程
            cleanup_thread = threading.Thread(
                target=self._cleanup_sessions, daemon=True
            )
            cleanup_thread.start()

            # 启动统计线程
            stats_thread = threading.Thread(target=self._print_stats, daemon=True)
            stats_thread.start()

            # 主接收循环
            while self.running:
                try:
                    data, client_addr = self.socket.recvfrom(self.config.buffer_size)

                    if data:
                        self.stats["packets_in"] += 1
                        self.stats["bytes_in"] += len(data)

                        # 处理数据包
                        self._handle_client_packet(data, client_addr)

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.logger.error(f"[UDP] 接收错误: {e}")

        except Exception as e:
            self.logger.error(f"[UDP] 启动失败: {e}")
        finally:
            self.stop()

    def _handle_client_packet(self, data: bytes, client_addr: Tuple[str, int]):
        """处理来自客户端的数据包"""

        with self.sessions_lock:
            if client_addr not in self.sessions:
                # 创建新会话
                try:
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    target_socket.setsockopt(
                        socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024
                    )
                    target_socket.setsockopt(
                        socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024
                    )
                    target_socket.settimeout(self.config.udp_timeout)

                    self.sessions[client_addr] = {
                        "socket": target_socket,
                        "last_active": time.time(),
                    }

                    self.logger.info(f"[UDP] 新会话: {client_addr[0]}:{client_addr[1]}")

                    # 启动接收线程
                    recv_thread = threading.Thread(
                        target=self._receive_from_target,
                        args=(client_addr,),
                        daemon=True,
                    )
                    recv_thread.start()

                except Exception as e:
                    self.logger.error(f"[UDP] 创建会话失败: {e}")
                    return
            else:
                self.sessions[client_addr]["last_active"] = time.time()

            target_socket = self.sessions[client_addr]["socket"]

        # 转发到目标服务器
        try:
            target_socket.sendto(
                data, (self.config.target_host, self.config.target_port)
            )
        except Exception as e:
            self.logger.error(f"[UDP] 转发到目标失败: {e}")

    def _receive_from_target(self, client_addr: Tuple[str, int]):
        """接收来自目标服务器的响应"""

        while self.running:
            with self.sessions_lock:
                if client_addr not in self.sessions:
                    break
                session = self.sessions[client_addr]
                target_socket = session["socket"]

            try:
                data, _ = target_socket.recvfrom(self.config.buffer_size)

                if data:
                    # 发送回客户端
                    self.socket.sendto(data, client_addr)

                    self.stats["packets_out"] += 1
                    self.stats["bytes_out"] += len(data)

                    with self.sessions_lock:
                        if client_addr in self.sessions:
                            self.sessions[client_addr]["last_active"] = time.time()

            except socket.timeout:
                # 检查会话是否超时
                with self.sessions_lock:
                    if client_addr in self.sessions:
                        if (
                            time.time() - self.sessions[client_addr]["last_active"]
                            > self.config.udp_timeout
                        ):
                            break
                continue
            except Exception as e:
                self.logger.debug(f"[UDP] 接收目标响应错误: {e}")
                break

        # 清理会话
        self._remove_session(client_addr)

    def _remove_session(self, client_addr: Tuple[str, int]):
        """移除会话"""
        with self.sessions_lock:
            if client_addr in self.sessions:
                try:
                    self.sessions[client_addr]["socket"].close()
                except:
                    pass
                del self.sessions[client_addr]
                self.logger.info(f"[UDP] 会话结束: {client_addr[0]}:{client_addr[1]}")

    def _cleanup_sessions(self):
        """定期清理过期会话"""
        while self.running:
            time.sleep(30)

            current_time = time.time()
            expired = []

            with self.sessions_lock:
                for addr, session in self.sessions.items():
                    if current_time - session["last_active"] > self.config.udp_timeout:
                        expired.append(addr)

            for addr in expired:
                self._remove_session(addr)
                self.logger.info(f"[UDP] 清理超时会话: {addr[0]}:{addr[1]}")

    def _print_stats(self):
        """定期打印统计信息"""
        while self.running:
            time.sleep(60)

            with self.sessions_lock:
                session_count = len(self.sessions)

            self.logger.info(
                f"[UDP] 统计 │ 活跃会话: {session_count} │ "
                f"入站: {self.stats['packets_in']}包/{self._format_bytes(self.stats['bytes_in'])} │ "
                f"出站: {self.stats['packets_out']}包/{self._format_bytes(self.stats['bytes_out'])}"
            )

    def _format_bytes(self, bytes_count: int) -> str:
        """格式化字节数"""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_count < 1024:
                return f"{bytes_count:.1f}{unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f}TB"

    def stop(self):
        """停止UDP转发服务"""
        self.running = False

        # 关闭所有会话
        with self.sessions_lock:
            for session in self.sessions.values():
                try:
                    session["socket"].close()
                except:
                    pass
            self.sessions.clear()

        # 关闭主socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

        self.logger.info("[UDP] ✗ 服务已停止")


# ==================== 主程序 ====================


class PortForwarder:
    """端口转发管理器"""

    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = setup_logger(self.config.log_level)

        self.tcp_forwarder: Optional[TCPForwarder] = None
        self.udp_forwarder: Optional[UDPForwarder] = None
        self.threads: list = []

    def _load_config(self) -> ForwardConfig:
        """加载配置文件"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return ForwardConfig.from_dict(data)
            except Exception as e:
                print(f"加载配置失败: {e}")
                return ForwardConfig()
        else:
            # 创建默认配置
            config = ForwardConfig()
            self._save_config(config)
            return config

    def _save_config(self, config: ForwardConfig):
        """保存配置文件"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(), f, indent=4, ensure_ascii=False)

    def print_banner(self):
        """打印横幅"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║               游戏服务器端口转发工具 v1.0                     ║
║                   支持 TCP / UDP 协议                        ║
╠══════════════════════════════════════════════════════════════╣
║  用法: 客户端 → 本服务器 → 目标游戏服务器                    ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def print_config(self):
        """打印当前配置"""
        self.logger.info("─" * 50)
        self.logger.info("当前配置:")
        self.logger.info(
            f"  监听地址: {self.config.listen_host}:{self.config.listen_port}"
        )
        self.logger.info(
            f"  目标地址: {self.config.target_host}:{self.config.target_port}"
        )
        self.logger.info(f"  TCP转发: {'启用' if self.config.enable_tcp else '禁用'}")
        self.logger.info(f"  UDP转发: {'启用' if self.config.enable_udp else '禁用'}")
        self.logger.info(f"  UDP超时: {self.config.udp_timeout}秒")
        self.logger.info("─" * 50)

    def start(self):
        """启动服务"""
        self.print_banner()
        self.print_config()

        # 启动TCP转发
        if self.config.enable_tcp:
            self.tcp_forwarder = TCPForwarder(self.config, self.logger)
            tcp_thread = threading.Thread(target=self.tcp_forwarder.start, daemon=True)
            tcp_thread.start()
            self.threads.append(tcp_thread)

        # 启动UDP转发
        if self.config.enable_udp:
            self.udp_forwarder = UDPForwarder(self.config, self.logger)
            udp_thread = threading.Thread(target=self.udp_forwarder.start, daemon=True)
            udp_thread.start()
            self.threads.append(udp_thread)

        if not self.threads:
            self.logger.error("未启用任何转发协议!")
            return

        self.logger.info("服务启动成功! 按 Ctrl+C 停止...")

        # 主循环
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("\n正在停止服务...")
            self.stop()

    def stop(self):
        """停止服务"""
        if self.tcp_forwarder:
            self.tcp_forwarder.stop()
        if self.udp_forwarder:
            self.udp_forwarder.stop()

        self.logger.info("所有服务已停止")


# ==================== 命令行入口 ====================


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="游戏服务器端口转发工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                           # 使用config.json配置
  %(prog)s -c myconfig.json          # 使用指定配置文件
  %(prog)s -l 0.0.0.0:54321 -t 1.2.3.4:19132   # 命令行指定
  %(prog)s --udp                     # 仅UDP模式(适合MCBE)
  %(prog)s --init                    # 生成配置文件模板
        """,
    )

    parser.add_argument(
        "-c", "--config", default="config.json", help="配置文件路径 (默认: config.json)"
    )
    parser.add_argument(
        "-l", "--listen", metavar="HOST:PORT", help="监听地址 (如: 0.0.0.0:54321)"
    )
    parser.add_argument(
        "-t", "--target", metavar="HOST:PORT", help="目标地址 (如: 192.168.1.100:19132)"
    )
    parser.add_argument("--tcp", action="store_true", help="仅启用TCP转发")
    parser.add_argument("--udp", action="store_true", help="仅启用UDP转发")
    parser.add_argument("--init", action="store_true", help="生成默认配置文件")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出模式")

    args = parser.parse_args()

    # 生成配置文件
    if args.init:
        config = ForwardConfig()
        config.target_host = "目标服务器IP"

        with open(args.config, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(), f, indent=4, ensure_ascii=False)

        print(f"✓ 配置文件已生成: {args.config}")
        print("  请编辑配置文件后重新运行程序")
        return

    # 创建转发器
    forwarder = PortForwarder(args.config)

    # 命令行参数覆盖配置
    if args.listen:
        try:
            host, port = args.listen.rsplit(":", 1)
            forwarder.config.listen_host = host
            forwarder.config.listen_port = int(port)
        except ValueError:
            print("错误: 监听地址格式应为 HOST:PORT")
            sys.exit(1)

    if args.target:
        try:
            host, port = args.target.rsplit(":", 1)
            forwarder.config.target_host = host
            forwarder.config.target_port = int(port)
        except ValueError:
            print("错误: 目标地址格式应为 HOST:PORT")
            sys.exit(1)

    if args.tcp and not args.udp:
        forwarder.config.enable_tcp = True
        forwarder.config.enable_udp = False
    elif args.udp and not args.tcp:
        forwarder.config.enable_tcp = False
        forwarder.config.enable_udp = True

    if args.verbose:
        forwarder.config.log_level = "DEBUG"
        forwarder.logger = setup_logger("DEBUG")

    # 启动服务
    forwarder.start()


if __name__ == "__main__":
    main()
