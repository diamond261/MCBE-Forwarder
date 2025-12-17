/*
 * IP 转发程序 - 多玩家支持版本
 * 用于游戏服务器转发 (MCBE等)
 * 架构: Multiple Clients -> Mid-Server(54321) -> Target-Server(19132)
 *
 * 多玩家原理:
 *   每个客户端IP:Port -> 独立的会话 -> 独立的socket到目标服务器
 *   Client1 (192.168.1.10:12345) -> Session1 -> Target
 *   Client2 (192.168.1.11:54321) -> Session2 -> Target
 *   ...
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstring>
#include <csignal>
#include <memory>
#include <iomanip>

// Linux 网络头文件
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// ==================== 日志级别 ====================
enum LogLevel
{
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

LogLevel g_log_level = LOG_INFO;

// ==================== 简易 JSON 解析器 ====================
class JsonValue
{
public:
    enum Type
    {
        NUL,
        BOOL,
        NUMBER,
        STRING,
        ARRAY,
        OBJECT
    };

    Type type = NUL;
    bool bool_val = false;
    double num_val = 0;
    std::string str_val;
    std::vector<JsonValue> arr_val;
    std::map<std::string, JsonValue> obj_val;

    JsonValue() : type(NUL) {}
    JsonValue(bool v) : type(BOOL), bool_val(v) {}
    JsonValue(double v) : type(NUMBER), num_val(v) {}
    JsonValue(int v) : type(NUMBER), num_val(v) {}
    JsonValue(const std::string &v) : type(STRING), str_val(v) {}
    JsonValue(const char *v) : type(STRING), str_val(v) {}

    bool as_bool(bool def = false) const
    {
        return type == BOOL ? bool_val : def;
    }

    int as_int(int def = 0) const
    {
        return type == NUMBER ? (int)num_val : def;
    }

    std::string as_string(const std::string &def = "") const
    {
        return type == STRING ? str_val : def;
    }

    const JsonValue &operator[](const std::string &key) const
    {
        static JsonValue null_val;
        if (type != OBJECT)
            return null_val;
        auto it = obj_val.find(key);
        return it != obj_val.end() ? it->second : null_val;
    }

    bool has(const std::string &key) const
    {
        return type == OBJECT && obj_val.find(key) != obj_val.end();
    }
};

class JsonParser
{
public:
    static JsonValue parse(const std::string &json)
    {
        size_t pos = 0;
        return parse_value(json, pos);
    }

    static JsonValue parse_file(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            throw std::runtime_error("无法打开文件: " + filename);
        }
        std::stringstream ss;
        ss << file.rdbuf();
        return parse(ss.str());
    }

private:
    static void skip_ws(const std::string &s, size_t &p)
    {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r'))
            p++;
    }

    static JsonValue parse_value(const std::string &s, size_t &p)
    {
        skip_ws(s, p);
        if (p >= s.size())
            return JsonValue();

        char c = s[p];
        if (c == '{')
            return parse_object(s, p);
        if (c == '[')
            return parse_array(s, p);
        if (c == '"')
            return parse_string(s, p);
        if (c == 't' || c == 'f')
            return parse_bool(s, p);
        if (c == 'n')
        {
            p += 4;
            return JsonValue();
        }
        if (c == '-' || (c >= '0' && c <= '9'))
            return parse_number(s, p);
        return JsonValue();
    }

    static JsonValue parse_object(const std::string &s, size_t &p)
    {
        JsonValue obj;
        obj.type = JsonValue::OBJECT;
        p++;
        skip_ws(s, p);
        if (p < s.size() && s[p] == '}')
        {
            p++;
            return obj;
        }

        while (p < s.size())
        {
            skip_ws(s, p);
            if (s[p] != '"')
                break;
            std::string key = parse_string(s, p).str_val;
            skip_ws(s, p);
            if (p >= s.size() || s[p] != ':')
                break;
            p++;
            obj.obj_val[key] = parse_value(s, p);
            skip_ws(s, p);
            if (p >= s.size())
                break;
            if (s[p] == '}')
            {
                p++;
                break;
            }
            if (s[p] == ',')
            {
                p++;
                continue;
            }
            break;
        }
        return obj;
    }

    static JsonValue parse_array(const std::string &s, size_t &p)
    {
        JsonValue arr;
        arr.type = JsonValue::ARRAY;
        p++;
        skip_ws(s, p);
        if (p < s.size() && s[p] == ']')
        {
            p++;
            return arr;
        }

        while (p < s.size())
        {
            arr.arr_val.push_back(parse_value(s, p));
            skip_ws(s, p);
            if (p >= s.size())
                break;
            if (s[p] == ']')
            {
                p++;
                break;
            }
            if (s[p] == ',')
            {
                p++;
                continue;
            }
            break;
        }
        return arr;
    }

    static JsonValue parse_string(const std::string &s, size_t &p)
    {
        p++;
        std::string r;
        while (p < s.size() && s[p] != '"')
        {
            if (s[p] == '\\' && p + 1 < s.size())
            {
                p++;
                switch (s[p])
                {
                case 'n':
                    r += '\n';
                    break;
                case 't':
                    r += '\t';
                    break;
                case 'r':
                    r += '\r';
                    break;
                default:
                    r += s[p];
                    break;
                }
            }
            else
            {
                r += s[p];
            }
            p++;
        }
        if (p < s.size())
            p++;
        return JsonValue(r);
    }

    static JsonValue parse_number(const std::string &s, size_t &p)
    {
        size_t start = p;
        if (s[p] == '-')
            p++;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9')
            p++;
        if (p < s.size() && s[p] == '.')
        {
            p++;
            while (p < s.size() && s[p] >= '0' && s[p] <= '9')
                p++;
        }
        return JsonValue(std::stod(s.substr(start, p - start)));
    }

    static JsonValue parse_bool(const std::string &s, size_t &p)
    {
        if (s.substr(p, 4) == "true")
        {
            p += 4;
            return JsonValue(true);
        }
        if (s.substr(p, 5) == "false")
        {
            p += 5;
            return JsonValue(false);
        }
        return JsonValue();
    }
};

// ==================== 配置类 ====================
struct Config
{
    std::string listen_host = "0.0.0.0";
    int listen_port = 54321;
    std::string target_host = "127.0.0.1";
    int target_port = 19132;
    bool enable_tcp = false;
    bool enable_udp = true;
    int buffer_size = 65535;
    int udp_timeout = 120;
    std::string log_level = "INFO";

    bool load(const std::string &filename)
    {
        try
        {
            JsonValue json = JsonParser::parse_file(filename);

            listen_host = json["listen_host"].as_string(listen_host);
            listen_port = json["listen_port"].as_int(listen_port);
            target_host = json["target_host"].as_string(target_host);
            target_port = json["target_port"].as_int(target_port);
            enable_tcp = json["enable_tcp"].as_bool(enable_tcp);
            enable_udp = json["enable_udp"].as_bool(enable_udp);
            buffer_size = json["buffer_size"].as_int(buffer_size);
            udp_timeout = json["udp_timeout"].as_int(udp_timeout);
            log_level = json["log_level"].as_string(log_level);

            // 设置日志级别
            if (log_level == "DEBUG")
                g_log_level = LOG_DEBUG;
            else if (log_level == "INFO")
                g_log_level = LOG_INFO;
            else if (log_level == "WARN")
                g_log_level = LOG_WARN;
            else if (log_level == "ERROR")
                g_log_level = LOG_ERROR;

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[错误] 解析配置失败: " << e.what() << std::endl;
            return false;
        }
    }

    void create_default(const std::string &filename)
    {
        std::ofstream file(filename);
        file << R"({
    "listen_host": "0.0.0.0",
    "listen_port": 54321,
    "target_host": "127.0.0.1",
    "target_port": 19132,
    "enable_tcp": false,
    "enable_udp": true,
    "buffer_size": 65535,
    "udp_timeout": 120,
    "log_level": "INFO"
})";
        file.close();
    }

    void print()
    {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════╗\n";
        std::cout << "║              配 置 信 息                     ║\n";
        std::cout << "╠══════════════════════════════════════════════╣\n";
        std::cout << "║ 监听地址: " << std::left << std::setw(34)
                  << (listen_host + ":" + std::to_string(listen_port)) << "║\n";
        std::cout << "║ 目标地址: " << std::left << std::setw(34)
                  << (target_host + ":" + std::to_string(target_port)) << "║\n";
        std::cout << "║ UDP转发:  " << std::left << std::setw(34)
                  << (enable_udp ? "开启" : "关闭") << "║\n";
        std::cout << "║ TCP转发:  " << std::left << std::setw(34)
                  << (enable_tcp ? "开启" : "关闭") << "║\n";
        std::cout << "║ 缓冲区:   " << std::left << std::setw(34)
                  << (std::to_string(buffer_size) + " bytes") << "║\n";
        std::cout << "║ UDP超时:  " << std::left << std::setw(34)
                  << (std::to_string(udp_timeout) + " 秒") << "║\n";
        std::cout << "║ 日志级别: " << std::left << std::setw(34)
                  << log_level << "║\n";
        std::cout << "╚══════════════════════════════════════════════╝\n";
    }
};

// ==================== 全局变量 ====================
Config g_config;
std::atomic<bool> g_running(true);
std::atomic<int> g_udp_sessions(0);
std::atomic<int> g_tcp_connections(0);
std::atomic<uint64_t> g_packets_in(0);
std::atomic<uint64_t> g_packets_out(0);
std::atomic<uint64_t> g_bytes_in(0);
std::atomic<uint64_t> g_bytes_out(0);

// ==================== 日志类 ====================
class Log
{
public:
    static std::string timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        char buf[32];
        strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&time));

        std::stringstream ss;
        ss << buf << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    static void debug(const std::string &msg)
    {
        if (g_log_level <= LOG_DEBUG)
            std::cout << timestamp() << " [DEBUG] " << msg << std::endl;
    }

    static void info(const std::string &msg)
    {
        if (g_log_level <= LOG_INFO)
            std::cout << timestamp() << " [INFO]  " << msg << std::endl;
    }

    static void warn(const std::string &msg)
    {
        if (g_log_level <= LOG_WARN)
            std::cout << timestamp() << " [WARN]  " << msg << std::endl;
    }

    static void error(const std::string &msg)
    {
        if (g_log_level <= LOG_ERROR)
            std::cerr << timestamp() << " [ERROR] " << msg << std::endl;
    }
};

// ==================== 工具函数 ====================
void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::string addr_to_string(const sockaddr_in &addr)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s:%d",
             inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return std::string(buf);
}

std::string format_bytes(uint64_t bytes)
{
    const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = bytes;
    while (size >= 1024 && unit < 3)
    {
        size /= 1024;
        unit++;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unit]);
    return std::string(buf);
}

// 解析主机名到IP
bool resolve_host(const std::string &host, sockaddr_in &addr)
{
    // 先尝试直接解析IP
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
    {
        return true;
    }

    // DNS解析
    struct hostent *he = gethostbyname(host.c_str());
    if (he && he->h_addr_list[0])
    {
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
        return true;
    }

    return false;
}

void signal_handler(int sig)
{
    (void)sig;
    std::cout << "\n";
    Log::info("收到退出信号，正在关闭...");
    g_running = false;
}

// ==================== UDP 会话 (每个玩家一个) ====================
struct UdpSession
{
    int server_socket;       // 到目标服务器的socket
    sockaddr_in client_addr; // 客户端地址
    std::chrono::steady_clock::time_point last_active;
    uint64_t packets_sent = 0;
    uint64_t packets_recv = 0;

    UdpSession() : server_socket(-1)
    {
        memset(&client_addr, 0, sizeof(client_addr));
        last_active = std::chrono::steady_clock::now();
    }

    ~UdpSession()
    {
        if (server_socket >= 0)
        {
            close(server_socket);
        }
    }

    void update_activity()
    {
        last_active = std::chrono::steady_clock::now();
    }

    int inactive_seconds() const
    {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(
                   now - last_active)
            .count();
    }
};

// ==================== UDP 转发器 (多玩家支持) ====================
class UdpForwarder
{
public:
    UdpForwarder() : listen_socket_(-1), running_(false) {}

    ~UdpForwarder() { stop(); }

    bool start()
    {
        // 创建监听socket
        listen_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (listen_socket_ < 0)
        {
            Log::error("UDP: 创建socket失败 - " + std::string(strerror(errno)));
            return false;
        }

        // 设置socket选项
        int opt = 1;
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        int buf_size = g_config.buffer_size;
        setsockopt(listen_socket_, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(listen_socket_, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

        // 绑定地址
        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(g_config.listen_port);

        if (!resolve_host(g_config.listen_host, listen_addr))
        {
            Log::error("UDP: 无法解析监听地址: " + g_config.listen_host);
            close(listen_socket_);
            return false;
        }

        if (bind(listen_socket_, (sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        {
            Log::error("UDP: 绑定失败 - " + std::string(strerror(errno)));
            close(listen_socket_);
            return false;
        }

        // 解析目标地址
        target_addr_.sin_family = AF_INET;
        target_addr_.sin_port = htons(g_config.target_port);
        if (!resolve_host(g_config.target_host, target_addr_))
        {
            Log::error("UDP: 无法解析目标地址: " + g_config.target_host);
            close(listen_socket_);
            return false;
        }

        set_nonblocking(listen_socket_);
        running_ = true;

        // 启动工作线程
        forward_thread_ = std::thread(&UdpForwarder::forward_loop, this);
        cleanup_thread_ = std::thread(&UdpForwarder::cleanup_loop, this);

        Log::info("UDP: 转发器启动 " + g_config.listen_host + ":" +
                  std::to_string(g_config.listen_port) + " -> " +
                  g_config.target_host + ":" + std::to_string(g_config.target_port));

        return true;
    }

    void stop()
    {
        running_ = false;

        if (listen_socket_ >= 0)
        {
            close(listen_socket_);
            listen_socket_ = -1;
        }

        if (forward_thread_.joinable() &&
            forward_thread_.get_id() != std::this_thread::get_id())
        {
            forward_thread_.join();
        }

        if (cleanup_thread_.joinable() &&
            cleanup_thread_.get_id() != std::this_thread::get_id())
        {
            cleanup_thread_.join();
        }

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
    }

    void print_sessions()
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);

        if (sessions_.empty())
        {
            std::cout << "  (无活动会话)\n";
            return;
        }

        for (const auto &pair : sessions_)
        {
            std::cout << "  " << pair.first
                      << " | 发送: " << pair.second->packets_sent
                      << " | 接收: " << pair.second->packets_recv
                      << " | 空闲: " << pair.second->inactive_seconds() << "s\n";
        }
    }

private:
    int listen_socket_;
    sockaddr_in target_addr_;
    std::atomic<bool> running_;
    std::thread forward_thread_;
    std::thread cleanup_thread_;

    std::mutex sessions_mutex_;
    std::map<std::string, std::shared_ptr<UdpSession>> sessions_;

    // 获取或创建会话
    std::shared_ptr<UdpSession> get_or_create_session(const sockaddr_in &client_addr)
    {
        std::string key = addr_to_string(client_addr);

        std::lock_guard<std::mutex> lock(sessions_mutex_);

        auto it = sessions_.find(key);
        if (it != sessions_.end())
        {
            return it->second;
        }

        // 创建新会话
        auto session = std::make_shared<UdpSession>();
        session->client_addr = client_addr;

        // 为此客户端创建独立的服务器socket
        session->server_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (session->server_socket < 0)
        {
            Log::error("UDP: 创建服务器socket失败");
            return nullptr;
        }

        // 连接到目标服务器 (使UDP可以用recv/send)
        if (connect(session->server_socket,
                    (sockaddr *)&target_addr_, sizeof(target_addr_)) < 0)
        {
            Log::error("UDP: 连接目标服务器失败");
            close(session->server_socket);
            return nullptr;
        }

        set_nonblocking(session->server_socket);
        sessions_[key] = session;
        g_udp_sessions++;

        Log::info("UDP: 新玩家连接 " + key + " (在线: " +
                  std::to_string(sessions_.size()) + ")");

        return session;
    }

    // 主转发循环
    void forward_loop()
    {
        std::vector<char> buffer(g_config.buffer_size);

        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_socket_, &read_fds);

            int max_fd = listen_socket_;

            // 收集所有会话的socket
            std::vector<std::pair<std::string, std::shared_ptr<UdpSession>>> active_sessions;
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                for (auto &pair : sessions_)
                {
                    if (pair.second->server_socket >= 0)
                    {
                        FD_SET(pair.second->server_socket, &read_fds);
                        max_fd = std::max(max_fd, pair.second->server_socket);
                        active_sessions.push_back(pair);
                    }
                }
            }

            timeval tv{0, 50000}; // 50ms超时
            int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // 1. 处理来自客户端的数据 -> 转发到服务器
            if (FD_ISSET(listen_socket_, &read_fds))
            {
                sockaddr_in client_addr{};
                socklen_t addr_len = sizeof(client_addr);

                ssize_t recv_len = recvfrom(listen_socket_, buffer.data(),
                                            buffer.size(), 0,
                                            (sockaddr *)&client_addr, &addr_len);

                if (recv_len > 0)
                {
                    g_packets_in++;
                    g_bytes_in += recv_len;

                    auto session = get_or_create_session(client_addr);
                    if (session)
                    {
                        ssize_t sent = send(session->server_socket,
                                            buffer.data(), recv_len, 0);
                        if (sent > 0)
                        {
                            g_packets_out++;
                            g_bytes_out += sent;
                            session->packets_sent++;
                            session->update_activity();

                            Log::debug("UDP: " + addr_to_string(client_addr) +
                                       " -> 服务器 (" + std::to_string(recv_len) + " bytes)");
                        }
                    }
                }
            }

            // 2. 处理来自服务器的响应 -> 转发回对应客户端
            for (auto &pair : active_sessions)
            {
                if (pair.second->server_socket >= 0 &&
                    FD_ISSET(pair.second->server_socket, &read_fds))
                {

                    ssize_t recv_len = recv(pair.second->server_socket,
                                            buffer.data(), buffer.size(), 0);

                    if (recv_len > 0)
                    {
                        g_packets_in++;
                        g_bytes_in += recv_len;

                        ssize_t sent = sendto(listen_socket_, buffer.data(), recv_len, 0,
                                              (sockaddr *)&pair.second->client_addr,
                                              sizeof(pair.second->client_addr));

                        if (sent > 0)
                        {
                            g_packets_out++;
                            g_bytes_out += sent;
                            pair.second->packets_recv++;
                            pair.second->update_activity();

                            Log::debug("UDP: 服务器 -> " + pair.first +
                                       " (" + std::to_string(recv_len) + " bytes)");
                        }
                    }
                }
            }
        }
    }

    // 清理过期会话
    void cleanup_loop()
    {
        while (running_ && g_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            std::vector<std::string> expired;

            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);

                for (auto &pair : sessions_)
                {
                    if (pair.second->inactive_seconds() > g_config.udp_timeout)
                    {
                        expired.push_back(pair.first);
                    }
                }

                for (const auto &key : expired)
                {
                    Log::info("UDP: 玩家超时断开 " + key);
                    sessions_.erase(key);
                    g_udp_sessions--;
                }
            }
        }
    }
};

// ==================== TCP 连接 (每个玩家一个) ====================
class TcpConnection : public std::enable_shared_from_this<TcpConnection>
{
public:
    TcpConnection(int client_fd, const sockaddr_in &client_addr)
        : client_fd_(client_fd), server_fd_(-1),
          client_addr_(client_addr), running_(false) {}

    ~TcpConnection() { stop(); }

    bool start()
    {
        // 连接到目标服务器
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0)
        {
            Log::error("TCP: 创建服务器socket失败");
            return false;
        }

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(g_config.target_port);

        if (!resolve_host(g_config.target_host, target_addr))
        {
            Log::error("TCP: 无法解析目标地址");
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        if (connect(server_fd_, (sockaddr *)&target_addr, sizeof(target_addr)) < 0)
        {
            Log::error("TCP: 连接目标服务器失败 - " + std::string(strerror(errno)));
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        running_ = true;
        g_tcp_connections++;

        Log::info("TCP: 新玩家连接 " + addr_to_string(client_addr_) +
                  " (在线: " + std::to_string(g_tcp_connections.load()) + ")");

        return true;
    }

    void run()
    {
        std::vector<char> buffer(g_config.buffer_size);

        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);

            if (client_fd_ >= 0)
                FD_SET(client_fd_, &read_fds);
            if (server_fd_ >= 0)
                FD_SET(server_fd_, &read_fds);

            int max_fd = std::max(client_fd_, server_fd_);

            timeval tv{1, 0};
            int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // 客户端 -> 服务器
            if (client_fd_ >= 0 && FD_ISSET(client_fd_, &read_fds))
            {
                ssize_t len = recv(client_fd_, buffer.data(), buffer.size(), 0);
                if (len <= 0)
                    break;

                g_packets_in++;
                g_bytes_in += len;

                ssize_t sent = send(server_fd_, buffer.data(), len, 0);
                if (sent <= 0)
                    break;

                g_packets_out++;
                g_bytes_out += sent;

                Log::debug("TCP: " + addr_to_string(client_addr_) +
                           " -> 服务器 (" + std::to_string(len) + " bytes)");
            }

            // 服务器 -> 客户端
            if (server_fd_ >= 0 && FD_ISSET(server_fd_, &read_fds))
            {
                ssize_t len = recv(server_fd_, buffer.data(), buffer.size(), 0);
                if (len <= 0)
                    break;

                g_packets_in++;
                g_bytes_in += len;

                ssize_t sent = send(client_fd_, buffer.data(), len, 0);
                if (sent <= 0)
                    break;

                g_packets_out++;
                g_bytes_out += sent;

                Log::debug("TCP: 服务器 -> " + addr_to_string(client_addr_) +
                           " (" + std::to_string(len) + " bytes)");
            }
        }

        stop();
    }

    void stop()
    {
        if (!running_.exchange(false))
            return;

        if (client_fd_ >= 0)
        {
            close(client_fd_);
            client_fd_ = -1;
        }
        if (server_fd_ >= 0)
        {
            close(server_fd_);
            server_fd_ = -1;
        }

        g_tcp_connections--;
        Log::info("TCP: 玩家断开 " + addr_to_string(client_addr_));
    }

private:
    int client_fd_;
    int server_fd_;
    sockaddr_in client_addr_;
    std::atomic<bool> running_;
};

// ==================== TCP 转发器 ====================
class TcpForwarder
{
public:
    TcpForwarder() : listen_socket_(-1), running_(false) {}

    ~TcpForwarder() { stop(); }

    bool start()
    {
        listen_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_socket_ < 0)
        {
            Log::error("TCP: 创建socket失败");
            return false;
        }

        int opt = 1;
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(g_config.listen_port);

        if (!resolve_host(g_config.listen_host, listen_addr))
        {
            Log::error("TCP: 无法解析监听地址");
            close(listen_socket_);
            return false;
        }

        if (bind(listen_socket_, (sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        {
            Log::error("TCP: 绑定失败 - " + std::string(strerror(errno)));
            close(listen_socket_);
            return false;
        }

        if (listen(listen_socket_, 128) < 0)
        {
            Log::error("TCP: 监听失败");
            close(listen_socket_);
            return false;
        }

        set_nonblocking(listen_socket_);
        running_ = true;

        accept_thread_ = std::thread(&TcpForwarder::accept_loop, this);

        Log::info("TCP: 转发器启动 " + g_config.listen_host + ":" +
                  std::to_string(g_config.listen_port));

        return true;
    }

    void stop()
    {
        running_ = false;

        if (listen_socket_ >= 0)
        {
            close(listen_socket_);
            listen_socket_ = -1;
        }

        if (accept_thread_.joinable() &&
            accept_thread_.get_id() != std::this_thread::get_id())
        {
            accept_thread_.join();
        }

        std::lock_guard<std::mutex> lock(threads_mutex_);
        for (auto &t : threads_)
        {
            if (t.joinable())
                t.join();
        }
        threads_.clear();
    }

private:
    int listen_socket_;
    std::atomic<bool> running_;
    std::thread accept_thread_;
    std::mutex threads_mutex_;
    std::vector<std::thread> threads_;

    void accept_loop()
    {
        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(listen_socket_, &read_fds);

            timeval tv{1, 0};
            if (select(listen_socket_ + 1, &read_fds, nullptr, nullptr, &tv) <= 0)
            {
                continue;
            }

            sockaddr_in client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            int client_fd = accept(listen_socket_, (sockaddr *)&client_addr, &addr_len);
            if (client_fd < 0)
                continue;

            auto conn = std::make_shared<TcpConnection>(client_fd, client_addr);
            if (conn->start())
            {
                std::lock_guard<std::mutex> lock(threads_mutex_);
                threads_.emplace_back([conn]()
                                      { conn->run(); });
            }
            else
            {
                close(client_fd);
            }
        }
    }
};

// ==================== 状态监控 ====================
void status_monitor(UdpForwarder *udp)
{
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        if (!g_running)
            break;

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════╗\n";
        std::cout << "║              运 行 状 态                     ║\n";
        std::cout << "╠══════════════════════════════════════════════╣\n";
        std::cout << "║ UDP会话: " << std::setw(8) << g_udp_sessions.load()
                  << " | TCP连接: " << std::setw(8) << g_tcp_connections.load() << "    ║\n";
        std::cout << "║ 收包数:  " << std::setw(8) << g_packets_in.load()
                  << " | 发包数:  " << std::setw(8) << g_packets_out.load() << "    ║\n";
        std::cout << "║ 接收:    " << std::setw(12) << format_bytes(g_bytes_in.load())
                  << " | 发送:    " << std::setw(12) << format_bytes(g_bytes_out.load()) << "║\n";
        std::cout << "╠══════════════════════════════════════════════╣\n";
        std::cout << "║ 活动玩家:                                    ║\n";

        if (udp)
        {
            udp->print_sessions();
        }

        std::cout << "╚══════════════════════════════════════════════╝\n";
    }
}

// ==================== 主函数 ====================
int main(int argc, char *argv[])
{
    std::cout << R"(
   ██╗██████╗     ███████╗ ██████╗ ██████╗ ██╗    ██╗ █████╗ ██████╗ ██████╗ 
   ██║██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔══██╗
   ██║██████╔╝    █████╗  ██║   ██║██████╔╝██║ █╗ ██║███████║██████╔╝██║  ██║
   ██║██╔═══╝     ██╔══╝  ██║   ██║██╔══██╗██║███╗██║██╔══██║██╔══██╗██║  ██║
   ██║██║         ██║     ╚██████╔╝██║  ██║╚███╔███╔╝██║  ██║██║  ██║██████╔╝
   ╚═╝╚═╝         ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                      游戏服务器转发工具 v3.0 (多玩家支持)
)" << std::endl;

    // 信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // 配置文件
    std::string config_file = "config.json";
    if (argc > 1)
    {
        config_file = argv[1];
    }

    // 检查配置文件
    std::ifstream check(config_file);
    if (!check.good())
    {
        Log::info("创建默认配置文件: " + config_file);
        g_config.create_default(config_file);
    }
    check.close();

    if (!g_config.load(config_file))
    {
        Log::warn("使用默认配置");
    }

    g_config.print();

    // 启动转发器
    std::unique_ptr<UdpForwarder> udp_forwarder;
    std::unique_ptr<TcpForwarder> tcp_forwarder;

    if (g_config.enable_udp)
    {
        udp_forwarder = std::make_unique<UdpForwarder>();
        if (!udp_forwarder->start())
        {
            Log::error("UDP转发器启动失败!");
            return 1;
        }
    }

    if (g_config.enable_tcp)
    {
        tcp_forwarder = std::make_unique<TcpForwarder>();
        if (!tcp_forwarder->start())
        {
            Log::error("TCP转发器启动失败!");
            return 1;
        }
    }

    // 状态监控线程
    std::thread monitor_thread(status_monitor, udp_forwarder.get());

    std::cout << "\n";
    Log::info("服务已启动，按 Ctrl+C 停止");
    std::cout << "\n";
    std::cout << "┌──────────────────────────────────────────────────────────┐\n";
    std::cout << "│                       转发规则                           │\n";
    std::cout << "├──────────────────────────────────────────────────────────┤\n";
    std::cout << "│  多个玩家 ──► " << g_config.listen_host << ":"
              << g_config.listen_port << " ──► "
              << g_config.target_host << ":" << g_config.target_port << "\n";
    std::cout << "│                                                          │\n";
    std::cout << "│  Player1 (独立会话) ──┐                                  │\n";
    std::cout << "│  Player2 (独立会话) ──┼──► 中转服务器 ──► 目标服务器     │\n";
    std::cout << "│  Player3 (独立会话) ──┘                                  │\n";
    std::cout << "└──────────────────────────────────────────────────────────┘\n";

    // 主循环
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n";
    Log::info("正在停止服务...");

    if (udp_forwarder)
        udp_forwarder->stop();
    if (tcp_forwarder)
        tcp_forwarder->stop();

    if (monitor_thread.joinable())
    {
        monitor_thread.join();
    }

    // 最终统计
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║              最 终 统 计                     ║\n";
    std::cout << "╠══════════════════════════════════════════════╣\n";
    std::cout << "║ 总收包: " << std::setw(15) << g_packets_in.load()
              << "                 ║\n";
    std::cout << "║ 总发包: " << std::setw(15) << g_packets_out.load()
              << "                 ║\n";
    std::cout << "║ 总接收: " << std::setw(15) << format_bytes(g_bytes_in.load())
              << "               ║\n";
    std::cout << "║ 总发送: " << std::setw(15) << format_bytes(g_bytes_out.load())
              << "               ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";

    Log::info("程序已退出");
    return 0;
}