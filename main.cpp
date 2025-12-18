/*
 * IP Forward - Game Server Proxy (MCBE, etc.)
 * Version: 4.0
 * Features:
 *   - Multi-player support
 *   - UDP/TCP forwarding
 *   - Daemon mode
 *   - File logging
 *   - Memory leak fixes
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <list>
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
#include <condition_variable>
#include <queue>
#include <functional>

// Linux headers
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// ==================== Log Level ====================
enum LogLevel
{
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

// ==================== Forward Declarations ====================
class Logger;
class Config;

// ==================== Global Variables ====================
std::atomic<bool> g_running(true);
std::atomic<int> g_udp_sessions(0);
std::atomic<int> g_tcp_connections(0);
std::atomic<uint64_t> g_packets_in(0);
std::atomic<uint64_t> g_packets_out(0);
std::atomic<uint64_t> g_bytes_in(0);
std::atomic<uint64_t> g_bytes_out(0);

// ==================== Simple JSON Parser ====================
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
            throw std::runtime_error("Cannot open file: " + filename);
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

// ==================== Configuration ====================
class Config
{
public:
    std::string listen_host = "0.0.0.0";
    int listen_port = 54321;
    std::string target_host = "127.0.0.1";
    int target_port = 19132;
    bool enable_tcp = false;
    bool enable_udp = true;
    int buffer_size = 65535;
    int udp_timeout = 120;
    std::string log_level = "INFO";
    std::string log_file = "forward.log";
    bool log_to_file = true;
    bool log_to_console = true;
    bool daemon_mode = false;
    int max_sessions = 1000;

    LogLevel get_log_level() const
    {
        if (log_level == "DEBUG")
            return LOG_DEBUG;
        if (log_level == "WARN")
            return LOG_WARN;
        if (log_level == "ERROR")
            return LOG_ERROR;
        return LOG_INFO;
    }

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
            log_file = json["log_file"].as_string(log_file);
            log_to_file = json["log_to_file"].as_bool(log_to_file);
            log_to_console = json["log_to_console"].as_bool(log_to_console);
            daemon_mode = json["daemon_mode"].as_bool(daemon_mode);
            max_sessions = json["max_sessions"].as_int(max_sessions);

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] Failed to parse config: " << e.what() << std::endl;
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
    "log_level": "INFO",
    "log_file": "forward.log",
    "log_to_file": true,
    "log_to_console": true,
    "daemon_mode": false,
    "max_sessions": 1000
})";
        file.close();
    }

    void print() const
    {
        std::cout << "\n";
        std::cout << "+----------------------------------------------+\n";
        std::cout << "|              CONFIGURATION                   |\n";
        std::cout << "+----------------------------------------------+\n";
        std::cout << "| Listen:     " << listen_host << ":" << listen_port << "\n";
        std::cout << "| Target:     " << target_host << ":" << target_port << "\n";
        std::cout << "| UDP:        " << (enable_udp ? "Enabled" : "Disabled") << "\n";
        std::cout << "| TCP:        " << (enable_tcp ? "Enabled" : "Disabled") << "\n";
        std::cout << "| Buffer:     " << buffer_size << " bytes\n";
        std::cout << "| Timeout:    " << udp_timeout << " seconds\n";
        std::cout << "| Log Level:  " << log_level << "\n";
        std::cout << "| Log File:   " << (log_to_file ? log_file : "Disabled") << "\n";
        std::cout << "| Daemon:     " << (daemon_mode ? "Yes" : "No") << "\n";
        std::cout << "| Max Sess:   " << max_sessions << "\n";
        std::cout << "+----------------------------------------------+\n";
    }
};

Config g_config;

// ==================== Logger ====================
class Logger
{
public:
    static Logger &instance()
    {
        static Logger inst;
        return inst;
    }

    void init(const std::string &filename, bool to_file, bool to_console, LogLevel level)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        level_ = level;
        to_file_ = to_file;
        to_console_ = to_console;

        if (to_file_ && !filename.empty())
        {
            file_.open(filename, std::ios::app);
            if (!file_.is_open())
            {
                std::cerr << "[WARN] Cannot open log file: " << filename << std::endl;
                to_file_ = false;
            }
        }
    }

    void close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open())
        {
            file_.close();
        }
    }

    void log(LogLevel level, const std::string &msg)
    {
        if (level < level_)
            return;

        std::string ts = timestamp();
        const char *prefix[] = {"[DEBUG]", "[INFO] ", "[WARN] ", "[ERROR]"};

        std::lock_guard<std::mutex> lock(mutex_);

        std::stringstream ss;
        ss << ts << " " << prefix[level] << " " << msg;
        std::string line = ss.str();

        if (to_console_)
        {
            std::cout << line << std::endl;
        }

        if (to_file_ && file_.is_open())
        {
            file_ << line << std::endl;
            file_.flush();
        }
    }

    static void debug(const std::string &msg) { instance().log(LOG_DEBUG, msg); }
    static void info(const std::string &msg) { instance().log(LOG_INFO, msg); }
    static void warn(const std::string &msg) { instance().log(LOG_WARN, msg); }
    static void error(const std::string &msg) { instance().log(LOG_ERROR, msg); }

private:
    Logger() : level_(LOG_INFO), to_file_(false), to_console_(true) {}
    ~Logger() { close(); }

    std::string timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&time));

        std::stringstream ss;
        ss << buf << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    std::mutex mutex_;
    std::ofstream file_;
    LogLevel level_;
    bool to_file_;
    bool to_console_;
};

// ==================== Utility Functions ====================
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

bool resolve_host(const std::string &host, sockaddr_in &addr)
{
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
    {
        return true;
    }
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
    g_running = false;
}

// Daemonize process
bool daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        return false;
    }
    if (pid > 0)
    {
        // Parent exits
        std::cout << "Started daemon with PID: " << pid << std::endl;
        exit(0);
    }

    // Child continues
    umask(0);

    if (setsid() < 0)
    {
        return false;
    }

    // Change working directory
    if (chdir("/") < 0)
    {
        return false;
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect to /dev/null
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2)
            close(fd);
    }

    return true;
}

// Write PID file
void write_pid_file(const std::string &filename)
{
    std::ofstream file(filename);
    if (file.is_open())
    {
        file << getpid();
        file.close();
    }
}

// Generate systemd service file
void generate_service_file(const std::string &exec_path, const std::string &config_path)
{
    std::string service = R"([Unit]
Description=IP Forward - Game Server Proxy
After=network.target

[Service]
Type=simple
ExecStart=)" + exec_path + " " +
                          config_path + R"(
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
)";

    std::ofstream file("ip_forward.service");
    if (file.is_open())
    {
        file << service;
        file.close();
        std::cout << "Generated: ip_forward.service\n";
        std::cout << "To install:\n";
        std::cout << "  sudo cp ip_forward.service /etc/systemd/system/\n";
        std::cout << "  sudo systemctl daemon-reload\n";
        std::cout << "  sudo systemctl enable ip_forward\n";
        std::cout << "  sudo systemctl start ip_forward\n";
    }
}

// ==================== Thread Pool (Fix Memory Leak) ====================
class ThreadPool
{
public:
    ThreadPool(size_t threads = 4) : stop_(false)
    {
        for (size_t i = 0; i < threads; ++i)
        {
            workers_.emplace_back([this]
                                  {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        cv_.wait(lock, [this] { 
                            return stop_ || !tasks_.empty(); 
                        });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                } });
        }
    }

    ~ThreadPool()
    {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto &worker : workers_)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

    template <class F>
    void enqueue(F &&f)
    {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (stop_)
                return;
            tasks_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_;
};

// ==================== UDP Session ====================
struct UdpSession
{
    int server_socket;
    sockaddr_in client_addr;
    std::chrono::steady_clock::time_point last_active;
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_recv{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};

    UdpSession() : server_socket(-1)
    {
        memset(&client_addr, 0, sizeof(client_addr));
        update_activity();
    }

    ~UdpSession()
    {
        if (server_socket >= 0)
        {
            close(server_socket);
            server_socket = -1;
        }
    }

    // Prevent copy
    UdpSession(const UdpSession &) = delete;
    UdpSession &operator=(const UdpSession &) = delete;

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

// ==================== UDP Forwarder ====================
class UdpForwarder
{
public:
    UdpForwarder() : listen_socket_(-1), running_(false) {}

    ~UdpForwarder()
    {
        stop();
    }

    bool start()
    {
        listen_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (listen_socket_ < 0)
        {
            Logger::error("UDP: Failed to create socket - " + std::string(strerror(errno)));
            return false;
        }

        int opt = 1;
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        int buf_size = g_config.buffer_size;
        setsockopt(listen_socket_, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(listen_socket_, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(g_config.listen_port);

        if (!resolve_host(g_config.listen_host, listen_addr))
        {
            Logger::error("UDP: Cannot resolve listen host: " + g_config.listen_host);
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        if (bind(listen_socket_, (sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        {
            Logger::error("UDP: Bind failed - " + std::string(strerror(errno)));
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        target_addr_.sin_family = AF_INET;
        target_addr_.sin_port = htons(g_config.target_port);
        if (!resolve_host(g_config.target_host, target_addr_))
        {
            Logger::error("UDP: Cannot resolve target host: " + g_config.target_host);
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        set_nonblocking(listen_socket_);
        running_ = true;

        forward_thread_ = std::thread(&UdpForwarder::forward_loop, this);
        cleanup_thread_ = std::thread(&UdpForwarder::cleanup_loop, this);

        Logger::info("UDP: Forwarder started " + g_config.listen_host + ":" +
                     std::to_string(g_config.listen_port) + " -> " +
                     g_config.target_host + ":" + std::to_string(g_config.target_port));

        return true;
    }

    void stop()
    {
        running_ = false;

        if (listen_socket_ >= 0)
        {
            shutdown(listen_socket_, SHUT_RDWR);
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

        // Clean up all sessions
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            size_t count = sessions_.size();
            sessions_.clear();
            g_udp_sessions = 0;
            if (count > 0)
            {
                Logger::info("UDP: Cleaned up " + std::to_string(count) + " sessions");
            }
        }

        Logger::info("UDP: Forwarder stopped");
    }

    void get_stats(size_t &sessions, uint64_t &bytes_in, uint64_t &bytes_out)
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions = sessions_.size();
        bytes_in = 0;
        bytes_out = 0;
        for (const auto &pair : sessions_)
        {
            bytes_in += pair.second->bytes_recv;
            bytes_out += pair.second->bytes_sent;
        }
    }

private:
    int listen_socket_;
    sockaddr_in target_addr_;
    std::atomic<bool> running_;
    std::thread forward_thread_;
    std::thread cleanup_thread_;

    std::mutex sessions_mutex_;
    std::map<std::string, std::unique_ptr<UdpSession>> sessions_;

    std::shared_ptr<UdpSession> get_or_create_session(const sockaddr_in &client_addr)
    {
        std::string key = addr_to_string(client_addr);

        std::lock_guard<std::mutex> lock(sessions_mutex_);

        auto it = sessions_.find(key);
        if (it != sessions_.end())
        {
            return std::shared_ptr<UdpSession>(std::shared_ptr<UdpSession>{}, it->second.get());
        }

        // Check session limit
        if ((int)sessions_.size() >= g_config.max_sessions)
        {
            Logger::warn("UDP: Max sessions reached (" + std::to_string(g_config.max_sessions) + ")");
            return nullptr;
        }

        auto session = std::make_unique<UdpSession>();
        session->client_addr = client_addr;

        session->server_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (session->server_socket < 0)
        {
            Logger::error("UDP: Failed to create server socket");
            return nullptr;
        }

        if (connect(session->server_socket,
                    (sockaddr *)&target_addr_, sizeof(target_addr_)) < 0)
        {
            Logger::error("UDP: Failed to connect to target server");
            close(session->server_socket);
            return nullptr;
        }

        set_nonblocking(session->server_socket);

        UdpSession *raw_ptr = session.get();
        sessions_[key] = std::move(session);
        g_udp_sessions++;

        Logger::info("UDP: New player connected " + key + " (online: " +
                     std::to_string(sessions_.size()) + ")");

        return std::shared_ptr<UdpSession>(std::shared_ptr<UdpSession>{}, raw_ptr);
    }

    void forward_loop()
    {
        std::vector<char> buffer(g_config.buffer_size);

        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);

            if (listen_socket_ < 0)
                break;
            FD_SET(listen_socket_, &read_fds);

            int max_fd = listen_socket_;

            std::vector<std::pair<std::string, UdpSession *>> active_sessions;
            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);
                for (auto &pair : sessions_)
                {
                    if (pair.second && pair.second->server_socket >= 0)
                    {
                        FD_SET(pair.second->server_socket, &read_fds);
                        max_fd = std::max(max_fd, pair.second->server_socket);
                        active_sessions.emplace_back(pair.first, pair.second.get());
                    }
                }
            }

            timeval tv{0, 50000}; // 50ms
            int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // Handle client -> server
            if (listen_socket_ >= 0 && FD_ISSET(listen_socket_, &read_fds))
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
                    if (session && session->server_socket >= 0)
                    {
                        ssize_t sent = send(session->server_socket,
                                            buffer.data(), recv_len, 0);
                        if (sent > 0)
                        {
                            g_packets_out++;
                            g_bytes_out += sent;
                            session->packets_sent++;
                            session->bytes_sent += sent;
                            session->update_activity();

                            Logger::debug("UDP: " + addr_to_string(client_addr) +
                                          " -> server (" + std::to_string(recv_len) + " bytes)");
                        }
                    }
                }
            }

            // Handle server -> client
            for (auto &pair : active_sessions)
            {
                if (pair.second && pair.second->server_socket >= 0 &&
                    FD_ISSET(pair.second->server_socket, &read_fds))
                {

                    ssize_t recv_len = recv(pair.second->server_socket,
                                            buffer.data(), buffer.size(), 0);

                    if (recv_len > 0)
                    {
                        g_packets_in++;
                        g_bytes_in += recv_len;

                        if (listen_socket_ >= 0)
                        {
                            ssize_t sent = sendto(listen_socket_, buffer.data(), recv_len, 0,
                                                  (sockaddr *)&pair.second->client_addr,
                                                  sizeof(pair.second->client_addr));

                            if (sent > 0)
                            {
                                g_packets_out++;
                                g_bytes_out += sent;
                                pair.second->packets_recv++;
                                pair.second->bytes_recv += sent;
                                pair.second->update_activity();

                                Logger::debug("UDP: server -> " + pair.first +
                                              " (" + std::to_string(recv_len) + " bytes)");
                            }
                        }
                    }
                }
            }
        }
    }

    void cleanup_loop()
    {
        while (running_ && g_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            if (!running_)
                break;

            std::vector<std::string> expired;

            {
                std::lock_guard<std::mutex> lock(sessions_mutex_);

                for (auto &pair : sessions_)
                {
                    if (pair.second &&
                        pair.second->inactive_seconds() > g_config.udp_timeout)
                    {
                        expired.push_back(pair.first);
                    }
                }

                for (const auto &key : expired)
                {
                    Logger::info("UDP: Player timeout " + key);
                    sessions_.erase(key);
                    g_udp_sessions--;
                }
            }
        }
    }
};

// ==================== TCP Connection ====================
class TcpConnection
{
public:
    TcpConnection(int client_fd, const sockaddr_in &client_addr)
        : client_fd_(client_fd), server_fd_(-1),
          client_addr_(client_addr), running_(false) {}

    ~TcpConnection()
    {
        stop();
    }

    // Prevent copy
    TcpConnection(const TcpConnection &) = delete;
    TcpConnection &operator=(const TcpConnection &) = delete;

    bool start()
    {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0)
        {
            Logger::error("TCP: Failed to create server socket");
            return false;
        }

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(g_config.target_port);

        if (!resolve_host(g_config.target_host, target_addr))
        {
            Logger::error("TCP: Cannot resolve target host");
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        // Set timeout for connect
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(server_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(server_fd_, (sockaddr *)&target_addr, sizeof(target_addr)) < 0)
        {
            Logger::error("TCP: Failed to connect to target - " + std::string(strerror(errno)));
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        running_ = true;
        g_tcp_connections++;

        Logger::info("TCP: New player connected " + addr_to_string(client_addr_) +
                     " (online: " + std::to_string(g_tcp_connections.load()) + ")");

        return true;
    }

    void run()
    {
        std::vector<char> buffer(g_config.buffer_size);

        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);

            if (client_fd_ < 0 || server_fd_ < 0)
                break;

            FD_SET(client_fd_, &read_fds);
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

            // Client -> Server
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

                Logger::debug("TCP: " + addr_to_string(client_addr_) +
                              " -> server (" + std::to_string(len) + " bytes)");
            }

            // Server -> Client
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

                Logger::debug("TCP: server -> " + addr_to_string(client_addr_) +
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
            shutdown(client_fd_, SHUT_RDWR);
            close(client_fd_);
            client_fd_ = -1;
        }
        if (server_fd_ >= 0)
        {
            shutdown(server_fd_, SHUT_RDWR);
            close(server_fd_);
            server_fd_ = -1;
        }

        g_tcp_connections--;
        Logger::info("TCP: Player disconnected " + addr_to_string(client_addr_));
    }

private:
    int client_fd_;
    int server_fd_;
    sockaddr_in client_addr_;
    std::atomic<bool> running_;
};

// ==================== TCP Forwarder ====================
class TcpForwarder
{
public:
    TcpForwarder() : listen_socket_(-1), running_(false), pool_(8) {}

    ~TcpForwarder()
    {
        stop();
    }

    bool start()
    {
        listen_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_socket_ < 0)
        {
            Logger::error("TCP: Failed to create socket");
            return false;
        }

        int opt = 1;
        setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_port = htons(g_config.listen_port);

        if (!resolve_host(g_config.listen_host, listen_addr))
        {
            Logger::error("TCP: Cannot resolve listen host");
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        if (bind(listen_socket_, (sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        {
            Logger::error("TCP: Bind failed - " + std::string(strerror(errno)));
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        if (listen(listen_socket_, 128) < 0)
        {
            Logger::error("TCP: Listen failed");
            close(listen_socket_);
            listen_socket_ = -1;
            return false;
        }

        set_nonblocking(listen_socket_);
        running_ = true;

        accept_thread_ = std::thread(&TcpForwarder::accept_loop, this);

        Logger::info("TCP: Forwarder started " + g_config.listen_host + ":" +
                     std::to_string(g_config.listen_port));

        return true;
    }

    void stop()
    {
        running_ = false;

        if (listen_socket_ >= 0)
        {
            shutdown(listen_socket_, SHUT_RDWR);
            close(listen_socket_);
            listen_socket_ = -1;
        }

        if (accept_thread_.joinable() &&
            accept_thread_.get_id() != std::this_thread::get_id())
        {
            accept_thread_.join();
        }

        // Clean up connections
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            for (auto &conn : connections_)
            {
                if (conn)
                    conn->stop();
            }
            connections_.clear();
        }

        Logger::info("TCP: Forwarder stopped");
    }

private:
    int listen_socket_;
    std::atomic<bool> running_;
    std::thread accept_thread_;
    ThreadPool pool_;

    std::mutex connections_mutex_;
    std::list<std::shared_ptr<TcpConnection>> connections_;

    void accept_loop()
    {
        while (running_ && g_running)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);

            if (listen_socket_ < 0)
                break;
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

            // Check connection limit
            if (g_tcp_connections >= g_config.max_sessions)
            {
                Logger::warn("TCP: Max connections reached");
                close(client_fd);
                continue;
            }

            auto conn = std::make_shared<TcpConnection>(client_fd, client_addr);
            if (conn->start())
            {
                {
                    std::lock_guard<std::mutex> lock(connections_mutex_);

                    // Clean up finished connections
                    connections_.remove_if([](const std::shared_ptr<TcpConnection> &c)
                                           { return !c || c.use_count() == 1; });

                    connections_.push_back(conn);
                }

                // Run in thread pool
                pool_.enqueue([conn]()
                              { conn->run(); });
            }
            else
            {
                close(client_fd);
            }
        }
    }
};

// ==================== Status Monitor ====================
void status_monitor()
{
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        if (!g_running)
            break;

        std::stringstream ss;
        ss << "Status | UDP: " << g_udp_sessions.load()
           << " | TCP: " << g_tcp_connections.load()
           << " | In: " << format_bytes(g_bytes_in.load())
           << " | Out: " << format_bytes(g_bytes_out.load())
           << " | Pkts: " << g_packets_in.load() << "/" << g_packets_out.load();

        Logger::info(ss.str());
    }
}

// ==================== Main ====================
void print_banner()
{
    std::cout << R"(
  ___ ____    _____                                _
 |_ _|  _ \  |  ___|__  _ ____      ____ _ _ __ __| |
  | || |_) | | |_ / _ \| '__\ \ /\ / / _` | '__/ _` |
  | ||  __/  |  _| (_) | |   \ V  V / (_| | | | (_| |
 |___|_|     |_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|
                                              v4.0
)" << std::endl;
}

void print_usage(const char *prog)
{
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <file>     Config file (default: config.json)\n";
    std::cout << "  -d, --daemon            Run as daemon\n";
    std::cout << "  -g, --generate-service  Generate systemd service file\n";
    std::cout << "  -h, --help              Show this help\n";
    std::cout << "\n";
}

int main(int argc, char *argv[])
{
    std::string config_file = "config.json";
    bool force_daemon = false;
    bool generate_service = false;

    // Parse arguments
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config")
        {
            if (i + 1 < argc)
            {
                config_file = argv[++i];
            }
        }
        else if (arg == "-d" || arg == "--daemon")
        {
            force_daemon = true;
        }
        else if (arg == "-g" || arg == "--generate-service")
        {
            generate_service = true;
        }
        else if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Generate service file and exit
    if (generate_service)
    {
        char exe_path[1024];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0)
        {
            exe_path[len] = '\0';
            generate_service_file(exe_path, config_file);
        }
        return 0;
    }

    print_banner();

    // Load or create config
    std::ifstream check(config_file);
    if (!check.good())
    {
        std::cout << "[INFO] Creating default config: " << config_file << std::endl;
        g_config.create_default(config_file);
    }
    check.close();

    if (!g_config.load(config_file))
    {
        std::cout << "[WARN] Using default configuration" << std::endl;
    }

    // Initialize logger
    Logger::instance().init(
        g_config.log_file,
        g_config.log_to_file,
        g_config.log_to_console,
        g_config.get_log_level());

    // Daemon mode
    if (force_daemon || g_config.daemon_mode)
    {
        std::cout << "[INFO] Starting in daemon mode..." << std::endl;
        if (!daemonize())
        {
            std::cerr << "[ERROR] Failed to daemonize" << std::endl;
            return 1;
        }
        write_pid_file("ip_forward.pid");
    }
    else
    {
        g_config.print();
    }

    // Signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // Start forwarders
    std::unique_ptr<UdpForwarder> udp_forwarder;
    std::unique_ptr<TcpForwarder> tcp_forwarder;

    if (g_config.enable_udp)
    {
        udp_forwarder = std::make_unique<UdpForwarder>();
        if (!udp_forwarder->start())
        {
            Logger::error("UDP forwarder failed to start!");
            return 1;
        }
    }

    if (g_config.enable_tcp)
    {
        tcp_forwarder = std::make_unique<TcpForwarder>();
        if (!tcp_forwarder->start())
        {
            Logger::error("TCP forwarder failed to start!");
            return 1;
        }
    }

    // Start monitor thread
    std::thread monitor_thread(status_monitor);

    Logger::info("Service started. Press Ctrl+C to stop.");
    Logger::info("Forwarding: " + g_config.listen_host + ":" +
                 std::to_string(g_config.listen_port) + " -> " +
                 g_config.target_host + ":" + std::to_string(g_config.target_port));

    // Main loop
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    Logger::info("Shutting down...");

    // Stop forwarders
    if (udp_forwarder)
        udp_forwarder->stop();
    if (tcp_forwarder)
        tcp_forwarder->stop();

    if (monitor_thread.joinable())
    {
        monitor_thread.join();
    }

    // Final stats
    Logger::info("=== Final Statistics ===");
    Logger::info("Total packets in:  " + std::to_string(g_packets_in.load()));
    Logger::info("Total packets out: " + std::to_string(g_packets_out.load()));
    Logger::info("Total bytes in:    " + format_bytes(g_bytes_in.load()));
    Logger::info("Total bytes out:   " + format_bytes(g_bytes_out.load()));

    Logger::info("Goodbye!");
    Logger::instance().close();

    // Remove PID file
    unlink("ip_forward.pid");

    return 0;
}