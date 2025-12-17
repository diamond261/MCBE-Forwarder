#ifndef PORT_FORWARDER_HPP
#define PORT_FORWARDER_HPP

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <functional>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>

// ==================== 平台检测 ====================
#ifdef _WIN32
#define PLATFORM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

typedef SOCKET socket_t;
typedef int socklen_t;
#define SOCKET_ERROR_CODE WSAGetLastError()
#define CLOSE_SOCKET(s) closesocket(s)
#define INVALID_SOCK INVALID_SOCKET
#else
#define PLATFORM_UNIX
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

typedef int socket_t;
#define SOCKET_ERROR_CODE errno
#define CLOSE_SOCKET(s) close(s)
#define INVALID_SOCK (-1)
#endif

namespace PortForwarder
{

    // ==================== 常量定义 ====================
    constexpr size_t DEFAULT_BUFFER_SIZE = 65535;
    constexpr int DEFAULT_UDP_TIMEOUT = 120;
    constexpr int DEFAULT_LISTEN_PORT = 54321;
    constexpr int DEFAULT_TARGET_PORT = 19132;

    // ==================== 日志级别 ====================
    enum class LogLevel
    {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3
    };

    // ==================== 配置结构 ====================
    struct Config
    {
        std::string listen_host = "0.0.0.0";
        int listen_port = DEFAULT_LISTEN_PORT;
        std::string target_host = "127.0.0.1";
        int target_port = DEFAULT_TARGET_PORT;
        bool enable_tcp = true;
        bool enable_udp = true;
        size_t buffer_size = DEFAULT_BUFFER_SIZE;
        int udp_timeout = DEFAULT_UDP_TIMEOUT;
        LogLevel log_level = LogLevel::INFO;

        bool loadFromFile(const std::string &path);
        bool saveToFile(const std::string &path) const;
        void print() const;
    };

    // ==================== 日志类 ====================
    class Logger
    {
    public:
        static Logger &instance();

        void setLevel(LogLevel level);
        void log(LogLevel level, const std::string &tag, const std::string &message);

        void debug(const std::string &tag, const std::string &msg);
        void info(const std::string &tag, const std::string &msg);
        void warning(const std::string &tag, const std::string &msg);
        void error(const std::string &tag, const std::string &msg);

    private:
        Logger() = default;
        LogLevel m_level = LogLevel::INFO;
        std::mutex m_mutex;

        std::string getLevelString(LogLevel level);
        std::string getTimestamp();
    };

    // ==================== 网络工具 ====================
    class NetworkUtils
    {
    public:
        static bool initialize();
        static void cleanup();
        static socket_t createSocket(int type);
        static bool setNonBlocking(socket_t sock, bool nonBlocking);
        static bool setReuseAddr(socket_t sock);
        static bool setBufferSize(socket_t sock, int size);
        static bool setTimeout(socket_t sock, int seconds);
        static void closeSocket(socket_t &sock);
        static std::string getErrorString();
        static std::string addressToString(const sockaddr_in &addr);
    };

    // ==================== UDP会话 ====================
    struct UDPSession
    {
        socket_t socket;
        sockaddr_in client_addr;
        std::chrono::steady_clock::time_point last_active;
        std::atomic<bool> running{true};
        std::thread recv_thread;

        UDPSession() : socket(INVALID_SOCK) {}
        ~UDPSession();
    };

    // ==================== TCP转发器 ====================
    class TCPForwarder
    {
    public:
        TCPForwarder(const Config &config);
        ~TCPForwarder();

        bool start();
        void stop();
        bool isRunning() const { return m_running; }

    private:
        void acceptLoop();
        void handleConnection(socket_t client_socket, sockaddr_in client_addr, int conn_id);
        void forwardData(socket_t source, socket_t dest,
                         const std::string &direction, std::atomic<bool> &stop_flag);

        Config m_config;
        socket_t m_server_socket;
        std::atomic<bool> m_running{false};
        std::atomic<int> m_connection_count{0};
        std::thread m_accept_thread;
        std::vector<std::thread> m_handler_threads;
        std::mutex m_threads_mutex;
    };

    // ==================== UDP转发器 ====================
    class UDPForwarder
    {
    public:
        UDPForwarder(const Config &config);
        ~UDPForwarder();

        bool start();
        void stop();
        bool isRunning() const { return m_running; }

    private:
        void receiveLoop();
        void handleClientPacket(const char *data, size_t len, const sockaddr_in &client_addr);
        void receiveFromTarget(const std::string &client_key);
        void cleanupSessions();
        void printStats();
        std::string makeClientKey(const sockaddr_in &addr);

        Config m_config;
        socket_t m_socket;
        std::atomic<bool> m_running{false};

        std::map<std::string, std::shared_ptr<UDPSession>> m_sessions;
        std::mutex m_sessions_mutex;

        std::thread m_recv_thread;
        std::thread m_cleanup_thread;
        std::thread m_stats_thread;

        // 统计
        std::atomic<uint64_t> m_packets_in{0};
        std::atomic<uint64_t> m_packets_out{0};
        std::atomic<uint64_t> m_bytes_in{0};
        std::atomic<uint64_t> m_bytes_out{0};
    };

    // ==================== 主管理器 ====================
    class ForwarderManager
    {
    public:
        ForwarderManager(const Config &config);
        ~ForwarderManager();

        bool start();
        void stop();
        void waitForShutdown();

        static void printBanner();

    private:
        Config m_config;
        std::unique_ptr<TCPForwarder> m_tcp_forwarder;
        std::unique_ptr<UDPForwarder> m_udp_forwarder;
        std::atomic<bool> m_running{false};
    };

} // namespace PortForwarder

#endif // PORT_FORWARDER_HPP