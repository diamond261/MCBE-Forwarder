/*
 * ================================================
 * IP/端口转发工具 - 游戏服务器转发
 * 适用于: Minecraft基岩版(MCBE)等游戏
 * 支持: TCP 和 UDP 协议
 * 编译: g++ -std=c++17 -O2 -pthread forwarder.cpp -o forwarder
 * ================================================
 */

#include "forwarder.hpp"
#include <csignal>
#include <cstdlib>
#include <algorithm>
#include <iomanip>

namespace PortForwarder
{

    // ==================== 全局信号处理 ====================
    static std::atomic<bool> g_shutdown_requested{false};

    void signalHandler(int signum)
    {
        (void)signum;
        g_shutdown_requested = true;
        std::cout << "\n[信号] 收到退出信号，正在关闭...\n";
    }

    // ==================== Config 实现 ====================

    bool Config::loadFromFile(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            return false;
        }

        std::string line;
        while (std::getline(file, line))
        {
            // 移除空白和注释
            size_t comment_pos = line.find("//");
            if (comment_pos != std::string::npos)
            {
                line = line.substr(0, comment_pos);
            }

            // 简单的JSON解析（键值对）
            size_t colon_pos = line.find(':');
            if (colon_pos == std::string::npos)
                continue;

            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);

            // 清理字符串
            auto trim = [](std::string &s)
            {
                const char *ws = " \t\n\r\f\v\"{}[],";
                s.erase(0, s.find_first_not_of(ws));
                s.erase(s.find_last_not_of(ws) + 1);
            };

            trim(key);
            trim(value);

            // 解析各个字段
            if (key == "listen_host")
                listen_host = value;
            else if (key == "listen_port")
                listen_port = std::stoi(value);
            else if (key == "target_host")
                target_host = value;
            else if (key == "target_port")
                target_port = std::stoi(value);
            else if (key == "enable_tcp")
                enable_tcp = (value == "true");
            else if (key == "enable_udp")
                enable_udp = (value == "true");
            else if (key == "buffer_size")
                buffer_size = std::stoull(value);
            else if (key == "udp_timeout")
                udp_timeout = std::stoi(value);
            else if (key == "log_level")
            {
                if (value == "DEBUG")
                    log_level = LogLevel::DEBUG;
                else if (value == "INFO")
                    log_level = LogLevel::INFO;
                else if (value == "WARNING")
                    log_level = LogLevel::WARNING;
                else if (value == "ERROR")
                    log_level = LogLevel::ERROR;
            }
        }

        return true;
    }

    bool Config::saveToFile(const std::string &path) const
    {
        std::ofstream file(path);
        if (!file.is_open())
        {
            return false;
        }

        file << "{\n";
        file << "    \"listen_host\": \"" << listen_host << "\",\n";
        file << "    \"listen_port\": " << listen_port << ",\n";
        file << "    \"target_host\": \"" << target_host << "\",\n";
        file << "    \"target_port\": " << target_port << ",\n";
        file << "    \"enable_tcp\": " << (enable_tcp ? "true" : "false") << ",\n";
        file << "    \"enable_udp\": " << (enable_udp ? "true" : "false") << ",\n";
        file << "    \"buffer_size\": " << buffer_size << ",\n";
        file << "    \"udp_timeout\": " << udp_timeout << ",\n";

        std::string level_str;
        switch (log_level)
        {
        case LogLevel::DEBUG:
            level_str = "DEBUG";
            break;
        case LogLevel::INFO:
            level_str = "INFO";
            break;
        case LogLevel::WARNING:
            level_str = "WARNING";
            break;
        case LogLevel::ERROR:
            level_str = "ERROR";
            break;
        }
        file << "    \"log_level\": \"" << level_str << "\"\n";
        file << "}\n";

        return true;
    }

    void Config::print() const
    {
        auto &log = Logger::instance();
        log.info("CONFIG", "══════════════════════════════════════════");
        log.info("CONFIG", "当前配置:");
        log.info("CONFIG", "  监听地址: " + listen_host + ":" + std::to_string(listen_port));
        log.info("CONFIG", "  目标地址: " + target_host + ":" + std::to_string(target_port));
        log.info("CONFIG", "  TCP转发: " + std::string(enable_tcp ? "启用" : "禁用"));
        log.info("CONFIG", "  UDP转发: " + std::string(enable_udp ? "启用" : "禁用"));
        log.info("CONFIG", "  缓冲区大小: " + std::to_string(buffer_size) + " 字节");
        log.info("CONFIG", "  UDP超时: " + std::to_string(udp_timeout) + " 秒");
        log.info("CONFIG", "══════════════════════════════════════════");
    }

    // ==================== Logger 实现 ====================

    Logger &Logger::instance()
    {
        static Logger instance;
        return instance;
    }

    void Logger::setLevel(LogLevel level)
    {
        m_level = level;
    }

    std::string Logger::getTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::tm tm_now;
#ifdef PLATFORM_WINDOWS
        localtime_s(&tm_now, &time_t_now);
#else
        localtime_r(&time_t_now, &tm_now);
#endif

        std::ostringstream oss;
        oss << std::put_time(&tm_now, "%H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    std::string Logger::getLevelString(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::DEBUG:
            return "\033[36mDEBUG\033[0m  ";
        case LogLevel::INFO:
            return "\033[32mINFO\033[0m   ";
        case LogLevel::WARNING:
            return "\033[33mWARN\033[0m   ";
        case LogLevel::ERROR:
            return "\033[31mERROR\033[0m  ";
        default:
            return "UNKN   ";
        }
    }

    void Logger::log(LogLevel level, const std::string &tag, const std::string &message)
    {
        if (level < m_level)
            return;

        std::lock_guard<std::mutex> lock(m_mutex);
        std::cout << getTimestamp() << " │ "
                  << getLevelString(level) << " │ "
                  << "[" << tag << "] " << message << std::endl;
    }

    void Logger::debug(const std::string &tag, const std::string &msg)
    {
        log(LogLevel::DEBUG, tag, msg);
    }

    void Logger::info(const std::string &tag, const std::string &msg)
    {
        log(LogLevel::INFO, tag, msg);
    }

    void Logger::warning(const std::string &tag, const std::string &msg)
    {
        log(LogLevel::WARNING, tag, msg);
    }

    void Logger::error(const std::string &tag, const std::string &msg)
    {
        log(LogLevel::ERROR, tag, msg);
    }

    // ==================== NetworkUtils 实现 ====================

    bool NetworkUtils::initialize()
    {
#ifdef PLATFORM_WINDOWS
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0)
        {
            Logger::instance().error("NET", "WSAStartup 失败: " + std::to_string(result));
            return false;
        }
#else
        // 忽略SIGPIPE信号
        signal(SIGPIPE, SIG_IGN);
#endif
        return true;
    }

    void NetworkUtils::cleanup()
    {
#ifdef PLATFORM_WINDOWS
        WSACleanup();
#endif
    }

    socket_t NetworkUtils::createSocket(int type)
    {
        socket_t sock = socket(AF_INET, type, 0);
        if (sock == INVALID_SOCK)
        {
            Logger::instance().error("NET", "创建socket失败: " + getErrorString());
        }
        return sock;
    }

    bool NetworkUtils::setNonBlocking(socket_t sock, bool nonBlocking)
    {
#ifdef PLATFORM_WINDOWS
        u_long mode = nonBlocking ? 1 : 0;
        return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1)
            return false;

        if (nonBlocking)
        {
            flags |= O_NONBLOCK;
        }
        else
        {
            flags &= ~O_NONBLOCK;
        }
        return fcntl(sock, F_SETFL, flags) == 0;
#endif
    }

    bool NetworkUtils::setReuseAddr(socket_t sock)
    {
        int opt = 1;
        return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                          reinterpret_cast<const char *>(&opt), sizeof(opt)) == 0;
    }

    bool NetworkUtils::setBufferSize(socket_t sock, int size)
    {
        bool success = true;
        success &= setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
                              reinterpret_cast<const char *>(&size), sizeof(size)) == 0;
        success &= setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
                              reinterpret_cast<const char *>(&size), sizeof(size)) == 0;
        return success;
    }

    bool NetworkUtils::setTimeout(socket_t sock, int seconds)
    {
#ifdef PLATFORM_WINDOWS
        DWORD timeout = seconds * 1000;
        return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                          reinterpret_cast<const char *>(&timeout), sizeof(timeout)) == 0;
#else
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                          reinterpret_cast<const char *>(&tv), sizeof(tv)) == 0;
#endif
    }

    void NetworkUtils::closeSocket(socket_t &sock)
    {
        if (sock != INVALID_SOCK)
        {
#ifdef PLATFORM_WINDOWS
            shutdown(sock, SD_BOTH);
#else
            shutdown(sock, SHUT_RDWR);
#endif
            CLOSE_SOCKET(sock);
            sock = INVALID_SOCK;
        }
    }

    std::string NetworkUtils::getErrorString()
    {
#ifdef PLATFORM_WINDOWS
        int error = WSAGetLastError();
        char *msg = nullptr;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                       nullptr, error, 0, reinterpret_cast<LPSTR>(&msg), 0, nullptr);
        std::string result = msg ? msg : "Unknown error";
        LocalFree(msg);
        return result;
#else
        return strerror(errno);
#endif
    }

    std::string NetworkUtils::addressToString(const sockaddr_in &addr)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }

    // ==================== UDPSession 实现 ====================

    UDPSession::~UDPSession()
    {
        running = false;
        if (recv_thread.joinable())
        {
            recv_thread.join();
        }
        if (socket != INVALID_SOCK)
        {
            NetworkUtils::closeSocket(socket);
        }
    }

    // ==================== TCPForwarder 实现 ====================

    TCPForwarder::TCPForwarder(const Config &config)
        : m_config(config), m_server_socket(INVALID_SOCK)
    {
    }

    TCPForwarder::~TCPForwarder()
    {
        stop();
    }

    bool TCPForwarder::start()
    {
        auto &log = Logger::instance();

        // 创建服务器socket
        m_server_socket = NetworkUtils::createSocket(SOCK_STREAM);
        if (m_server_socket == INVALID_SOCK)
        {
            return false;
        }

        NetworkUtils::setReuseAddr(m_server_socket);

        // 绑定地址
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(m_config.listen_port);
        inet_pton(AF_INET, m_config.listen_host.c_str(), &server_addr.sin_addr);

        if (bind(m_server_socket, reinterpret_cast<sockaddr *>(&server_addr),
                 sizeof(server_addr)) < 0)
        {
            log.error("TCP", "绑定端口失败: " + NetworkUtils::getErrorString());
            NetworkUtils::closeSocket(m_server_socket);
            return false;
        }

        // 开始监听
        if (listen(m_server_socket, 100) < 0)
        {
            log.error("TCP", "监听失败: " + NetworkUtils::getErrorString());
            NetworkUtils::closeSocket(m_server_socket);
            return false;
        }

        // 设置超时以便能够优雅退出
        NetworkUtils::setTimeout(m_server_socket, 1);

        m_running = true;
        m_accept_thread = std::thread(&TCPForwarder::acceptLoop, this);

        log.info("TCP", "✓ 监听启动 " + m_config.listen_host + ":" +
                            std::to_string(m_config.listen_port));

        return true;
    }

    void TCPForwarder::stop()
    {
        m_running = false;

        NetworkUtils::closeSocket(m_server_socket);

        if (m_accept_thread.joinable())
        {
            m_accept_thread.join();
        }

        // 等待所有处理线程
        std::lock_guard<std::mutex> lock(m_threads_mutex);
        for (auto &t : m_handler_threads)
        {
            if (t.joinable())
            {
                t.join();
            }
        }
        m_handler_threads.clear();

        Logger::instance().info("TCP", "✗ 服务已停止");
    }

    void TCPForwarder::acceptLoop()
    {
        auto &log = Logger::instance();

        while (m_running && !g_shutdown_requested)
        {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            socket_t client_socket = accept(m_server_socket,
                                            reinterpret_cast<sockaddr *>(&client_addr),
                                            &client_len);

            if (client_socket == INVALID_SOCK)
            {
                // 超时或错误
                continue;
            }

            int conn_id = ++m_connection_count;
            log.info("TCP", "新连接 #" + std::to_string(conn_id) +
                                " 来自 " + NetworkUtils::addressToString(client_addr));

            // 启动处理线程
            std::lock_guard<std::mutex> lock(m_threads_mutex);
            m_handler_threads.emplace_back(&TCPForwarder::handleConnection, this,
                                           client_socket, client_addr, conn_id);
        }
    }

    void TCPForwarder::handleConnection(socket_t client_socket, sockaddr_in client_addr, int conn_id)
    {
        auto &log = Logger::instance();
        socket_t target_socket = INVALID_SOCK;

        auto cleanup = [&]()
        {
            NetworkUtils::closeSocket(client_socket);
            NetworkUtils::closeSocket(target_socket);
            log.info("TCP", "#" + std::to_string(conn_id) + " 连接已关闭");
        };

        // 连接到目标服务器
        target_socket = NetworkUtils::createSocket(SOCK_STREAM);
        if (target_socket == INVALID_SOCK)
        {
            cleanup();
            return;
        }

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(m_config.target_port);
        inet_pton(AF_INET, m_config.target_host.c_str(), &target_addr.sin_addr);

        // 设置连接超时
        NetworkUtils::setTimeout(target_socket, 10);

        if (connect(target_socket, reinterpret_cast<sockaddr *>(&target_addr),
                    sizeof(target_addr)) < 0)
        {
            log.warning("TCP", "#" + std::to_string(conn_id) + " 连接目标服务器失败");
            cleanup();
            return;
        }

        log.info("TCP", "#" + std::to_string(conn_id) + " 已连接到目标服务器");

        // 重置超时
        NetworkUtils::setTimeout(target_socket, 0);
        NetworkUtils::setTimeout(client_socket, 0);

        // 双向转发
        std::atomic<bool> stop_flag{false};

        std::thread t1(&TCPForwarder::forwardData, this, client_socket, target_socket,
                       "#" + std::to_string(conn_id) + " C→S", std::ref(stop_flag));
        std::thread t2(&TCPForwarder::forwardData, this, target_socket, client_socket,
                       "#" + std::to_string(conn_id) + " S→C", std::ref(stop_flag));

        t1.join();
        t2.join();

        cleanup();
    }

    void TCPForwarder::forwardData(socket_t source, socket_t dest,
                                   const std::string &direction, std::atomic<bool> &stop_flag)
    {
        auto &log = Logger::instance();
        std::vector<char> buffer(m_config.buffer_size);
        uint64_t total_bytes = 0;

        // 设置读取超时
        NetworkUtils::setTimeout(source, 1);

        while (m_running && !stop_flag && !g_shutdown_requested)
        {
            int received = recv(source, buffer.data(), buffer.size(), 0);

            if (received > 0)
            {
                int sent = 0;
                while (sent < received)
                {
                    int n = send(dest, buffer.data() + sent, received - sent, 0);
                    if (n <= 0)
                    {
                        stop_flag = true;
                        break;
                    }
                    sent += n;
                }
                total_bytes += received;
            }
            else if (received == 0)
            {
                // 连接关闭
                break;
            }
            else
            {
                // 检查是否是超时
#ifdef PLATFORM_WINDOWS
                if (WSAGetLastError() == WSAETIMEDOUT)
                    continue;
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
#endif
                break;
            }
        }

        stop_flag = true;
        log.debug("TCP", direction + " 传输完成, 共 " + std::to_string(total_bytes) + " 字节");
    }

    // ==================== UDPForwarder 实现 ====================

    UDPForwarder::UDPForwarder(const Config &config)
        : m_config(config), m_socket(INVALID_SOCK)
    {
    }

    UDPForwarder::~UDPForwarder()
    {
        stop();
    }

    bool UDPForwarder::start()
    {
        auto &log = Logger::instance();

        // 创建UDP socket
        m_socket = NetworkUtils::createSocket(SOCK_DGRAM);
        if (m_socket == INVALID_SOCK)
        {
            return false;
        }

        NetworkUtils::setReuseAddr(m_socket);
        NetworkUtils::setBufferSize(m_socket, 1024 * 1024);
        NetworkUtils::setTimeout(m_socket, 1);

        // 绑定地址
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(m_config.listen_port);
        inet_pton(AF_INET, m_config.listen_host.c_str(), &server_addr.sin_addr);

        if (bind(m_socket, reinterpret_cast<sockaddr *>(&server_addr),
                 sizeof(server_addr)) < 0)
        {
            log.error("UDP", "绑定端口失败: " + NetworkUtils::getErrorString());
            NetworkUtils::closeSocket(m_socket);
            return false;
        }

        m_running = true;

        // 启动各个线程
        m_recv_thread = std::thread(&UDPForwarder::receiveLoop, this);
        m_cleanup_thread = std::thread(&UDPForwarder::cleanupSessions, this);
        m_stats_thread = std::thread(&UDPForwarder::printStats, this);

        log.info("UDP", "✓ 监听启动 " + m_config.listen_host + ":" +
                            std::to_string(m_config.listen_port));

        return true;
    }

    void UDPForwarder::stop()
    {
        m_running = false;

        // 关闭所有会话
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            for (auto &pair : m_sessions)
            {
                pair.second->running = false;
            }
            m_sessions.clear();
        }

        NetworkUtils::closeSocket(m_socket);

        if (m_recv_thread.joinable())
            m_recv_thread.join();
        if (m_cleanup_thread.joinable())
            m_cleanup_thread.join();
        if (m_stats_thread.joinable())
            m_stats_thread.join();

        Logger::instance().info("UDP", "✗ 服务已停止");
    }

    std::string UDPForwarder::makeClientKey(const sockaddr_in &addr)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }

    void UDPForwarder::receiveLoop()
    {
        auto &log = Logger::instance();
        std::vector<char> buffer(m_config.buffer_size);

        while (m_running && !g_shutdown_requested)
        {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);

            int received = recvfrom(m_socket, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<sockaddr *>(&client_addr),
                                    &client_len);

            if (received > 0)
            {
                m_packets_in++;
                m_bytes_in += received;
                handleClientPacket(buffer.data(), received, client_addr);
            }
        }
    }

    void UDPForwarder::handleClientPacket(const char *data, size_t len,
                                          const sockaddr_in &client_addr)
    {
        auto &log = Logger::instance();
        std::string client_key = makeClientKey(client_addr);

        std::shared_ptr<UDPSession> session;

        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);

            auto it = m_sessions.find(client_key);
            if (it == m_sessions.end())
            {
                // 创建新会话
                session = std::make_shared<UDPSession>();
                session->socket = NetworkUtils::createSocket(SOCK_DGRAM);

                if (session->socket == INVALID_SOCK)
                {
                    log.error("UDP", "创建会话socket失败");
                    return;
                }

                NetworkUtils::setBufferSize(session->socket, 1024 * 1024);
                NetworkUtils::setTimeout(session->socket, m_config.udp_timeout);

                session->client_addr = client_addr;
                session->last_active = std::chrono::steady_clock::now();

                m_sessions[client_key] = session;

                log.info("UDP", "新会话: " + client_key);

                // 启动接收线程
                session->recv_thread = std::thread(&UDPForwarder::receiveFromTarget,
                                                   this, client_key);
            }
            else
            {
                session = it->second;
                session->last_active = std::chrono::steady_clock::now();
            }
        }

        // 转发到目标服务器
        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(m_config.target_port);
        inet_pton(AF_INET, m_config.target_host.c_str(), &target_addr.sin_addr);

        sendto(session->socket, data, len, 0,
               reinterpret_cast<sockaddr *>(&target_addr), sizeof(target_addr));
    }

    void UDPForwarder::receiveFromTarget(const std::string &client_key)
    {
        auto &log = Logger::instance();
        std::vector<char> buffer(m_config.buffer_size);

        while (m_running && !g_shutdown_requested)
        {
            std::shared_ptr<UDPSession> session;

            {
                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                auto it = m_sessions.find(client_key);
                if (it == m_sessions.end() || !it->second->running)
                {
                    break;
                }
                session = it->second;
            }

            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);

            int received = recvfrom(session->socket, buffer.data(), buffer.size(), 0,
                                    reinterpret_cast<sockaddr *>(&from_addr), &from_len);

            if (received > 0)
            {
                // 发送回客户端
                sendto(m_socket, buffer.data(), received, 0,
                       reinterpret_cast<sockaddr *>(&session->client_addr),
                       sizeof(session->client_addr));

                m_packets_out++;
                m_bytes_out += received;

                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                auto it = m_sessions.find(client_key);
                if (it != m_sessions.end())
                {
                    it->second->last_active = std::chrono::steady_clock::now();
                }
            }
            else if (received < 0)
            {
                // 检查超时
#ifdef PLATFORM_WINDOWS
                if (WSAGetLastError() == WSAETIMEDOUT)
                {
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
#endif
                    // 检查会话是否超时
                    auto now = std::chrono::steady_clock::now();
                    std::lock_guard<std::mutex> lock(m_sessions_mutex);
                    auto it = m_sessions.find(client_key);
                    if (it != m_sessions.end())
                    {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                           now - it->second->last_active)
                                           .count();
                        if (elapsed > m_config.udp_timeout)
                        {
                            break;
                        }
                    }
                    continue;
                }
                break;
            }
        }

        // 清理会话
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            auto it = m_sessions.find(client_key);
            if (it != m_sessions.end())
            {
                it->second->running = false;
                m_sessions.erase(it);
                log.info("UDP", "会话结束: " + client_key);
            }
        }
    }

    void UDPForwarder::cleanupSessions()
    {
        while (m_running && !g_shutdown_requested)
        {
            std::this_thread::sleep_for(std::chrono::seconds(30));

            auto now = std::chrono::steady_clock::now();
            std::vector<std::string> expired;

            {
                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                for (auto &pair : m_sessions)
                {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                       now - pair.second->last_active)
                                       .count();
                    if (elapsed > m_config.udp_timeout)
                    {
                        expired.push_back(pair.first);
                    }
                }
            }

            for (const auto &key : expired)
            {
                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                auto it = m_sessions.find(key);
                if (it != m_sessions.end())
                {
                    it->second->running = false;
                    m_sessions.erase(it);
                    Logger::instance().info("UDP", "清理超时会话: " + key);
                }
            }
        }
    }

    void UDPForwarder::printStats()
    {
        auto formatBytes = [](uint64_t bytes) -> std::string
        {
            const char *units[] = {"B", "KB", "MB", "GB"};
            int unit_index = 0;
            double size = static_cast<double>(bytes);

            while (size >= 1024 && unit_index < 3)
            {
                size /= 1024;
                unit_index++;
            }

            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << size << units[unit_index];
            return oss.str();
        };

        while (m_running && !g_shutdown_requested)
        {
            std::this_thread::sleep_for(std::chrono::seconds(60));

            size_t session_count;
            {
                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                session_count = m_sessions.size();
            }

            Logger::instance().info("UDP",
                                    "统计 │ 活跃会话: " + std::to_string(session_count) +
                                        " │ 入站: " + std::to_string(m_packets_in.load()) + "包/" + formatBytes(m_bytes_in) +
                                        " │ 出站: " + std::to_string(m_packets_out.load()) + "包/" + formatBytes(m_bytes_out));
        }
    }

    // ==================== ForwarderManager 实现 ====================

    ForwarderManager::ForwarderManager(const Config &config)
        : m_config(config)
    {
    }

    ForwarderManager::~ForwarderManager()
    {
        stop();
    }

    void ForwarderManager::printBanner()
    {
        std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║              游戏服务器端口转发工具 v1.0 (C++)               ║
║                    支持 TCP / UDP 协议                       ║
╠══════════════════════════════════════════════════════════════╣
║   用法: 客户端 → 本服务器 → 目标游戏服务器                   ║
╚══════════════════════════════════════════════════════════════╝
)" << std::endl;
    }

    bool ForwarderManager::start()
    {
        printBanner();

        // 设置日志级别
        Logger::instance().setLevel(m_config.log_level);

        // 打印配置
        m_config.print();

        // 初始化网络
        if (!NetworkUtils::initialize())
        {
            return false;
        }

        m_running = true;

        // 启动TCP转发
        if (m_config.enable_tcp)
        {
            m_tcp_forwarder = std::make_unique<TCPForwarder>(m_config);
            if (!m_tcp_forwarder->start())
            {
                Logger::instance().error("MAIN", "TCP转发启动失败");
            }
        }

        // 启动UDP转发
        if (m_config.enable_udp)
        {
            m_udp_forwarder = std::make_unique<UDPForwarder>(m_config);
            if (!m_udp_forwarder->start())
            {
                Logger::instance().error("MAIN", "UDP转发启动失败");
            }
        }

        if (!m_tcp_forwarder && !m_udp_forwarder)
        {
            Logger::instance().error("MAIN", "没有成功启动的转发服务!");
            return false;
        }

        Logger::instance().info("MAIN", "服务启动成功! 按 Ctrl+C 停止...");

        return true;
    }

    void ForwarderManager::stop()
    {
        if (!m_running)
            return;
        m_running = false;

        if (m_tcp_forwarder)
        {
            m_tcp_forwarder->stop();
            m_tcp_forwarder.reset();
        }

        if (m_udp_forwarder)
        {
            m_udp_forwarder->stop();
            m_udp_forwarder.reset();
        }

        NetworkUtils::cleanup();
        Logger::instance().info("MAIN", "所有服务已停止");
    }

    void ForwarderManager::waitForShutdown()
    {
        while (m_running && !g_shutdown_requested)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        stop();
    }

} // namespace PortForwarder

// ==================== main 函数 ====================

void printHelp(const char *prog)
{
    std::cout << "游戏服务器端口转发工具\n\n"
              << "用法: " << prog << " [选项]\n\n"
              << "选项:\n"
              << "  -c, --config FILE    配置文件路径 (默认: config.json)\n"
              << "  -l, --listen ADDR    监听地址 (格式: HOST:PORT)\n"
              << "  -t, --target ADDR    目标地址 (格式: HOST:PORT)\n"
              << "  --tcp                仅启用TCP转发\n"
              << "  --udp                仅启用UDP转发\n"
              << "  --init               生成默认配置文件\n"
              << "  -v, --verbose        详细日志模式\n"
              << "  -h, --help           显示帮助\n\n"
              << "示例:\n"
              << "  " << prog << "                              # 使用config.json\n"
              << "  " << prog << " -l 0.0.0.0:54321 -t 1.2.3.4:19132\n"
              << "  " << prog << " --udp                        # 仅UDP(MCBE推荐)\n";
}

bool parseAddress(const std::string &addr, std::string &host, int &port)
{
    size_t pos = addr.rfind(':');
    if (pos == std::string::npos)
        return false;
    host = addr.substr(0, pos);
    port = std::stoi(addr.substr(pos + 1));
    return true;
}

int main(int argc, char *argv[])
{
    using namespace PortForwarder;

    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
#ifdef PLATFORM_UNIX
    signal(SIGHUP, signalHandler);
#endif

    Config config;
    std::string config_path = "config.json";
    bool init_mode = false;
    bool tcp_only = false;
    bool udp_only = false;
    bool verbose = false;

    // 解析命令行参数
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "-c" || arg == "--config")
        {
            if (i + 1 < argc)
            {
                config_path = argv[++i];
            }
        }
        else if (arg == "-l" || arg == "--listen")
        {
            if (i + 1 < argc)
            {
                if (!parseAddress(argv[++i], config.listen_host, config.listen_port))
                {
                    std::cerr << "错误: 监听地址格式无效\n";
                    return 1;
                }
            }
        }
        else if (arg == "-t" || arg == "--target")
        {
            if (i + 1 < argc)
            {
                if (!parseAddress(argv[++i], config.target_host, config.target_port))
                {
                    std::cerr << "错误: 目标地址格式无效\n";
                    return 1;
                }
            }
        }
        else if (arg == "--tcp")
        {
            tcp_only = true;
        }
        else if (arg == "--udp")
        {
            udp_only = true;
        }
        else if (arg == "--init")
        {
            init_mode = true;
        }
        else if (arg == "-v" || arg == "--verbose")
        {
            verbose = true;
        }
    }

    // 初始化模式
    if (init_mode)
    {
        config.target_host = "目标服务器IP";
        if (config.saveToFile(config_path))
        {
            std::cout << "✓ 配置文件已生成: " << config_path << "\n"
                      << "  请编辑配置文件后重新运行程序\n";
            return 0;
        }
        else
        {
            std::cerr << "错误: 无法创建配置文件\n";
            return 1;
        }
    }

    // 加载配置文件
    if (!config.loadFromFile(config_path))
    {
        std::cout << "未找到配置文件，使用默认配置\n";
    }

    // 应用命令行选项
    if (tcp_only)
    {
        config.enable_tcp = true;
        config.enable_udp = false;
    }
    if (udp_only)
    {
        config.enable_tcp = false;
        config.enable_udp = true;
    }
    if (verbose)
    {
        config.log_level = LogLevel::DEBUG;
    }

    // 启动转发器
    ForwarderManager manager(config);

    if (!manager.start())
    {
        return 1;
    }

    manager.waitForShutdown();

    return 0;
}