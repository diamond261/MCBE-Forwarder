/*
 * IP Forward - Game Server Proxy
 * Version: 1.2.1
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <thread>
#include <mutex>
#include <shared_mutex>
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
#include <algorithm>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>

#define VERSION "1.2.1"
#define MAX_POLL_FDS 4096

// ==================== Log Level ====================
enum LogLevel
{
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

// ==================== Safe Atomic Flag ====================
class SafeFlag
{
public:
    SafeFlag() : flag_(false) {}
    explicit SafeFlag(bool v) : flag_(v) {}

    void set(bool v) { flag_.store(v, std::memory_order_seq_cst); }
    bool get() const { return flag_.load(std::memory_order_seq_cst); }
    bool exchange(bool v) { return flag_.exchange(v, std::memory_order_seq_cst); }

    operator bool() const { return get(); }
    SafeFlag &operator=(bool v)
    {
        set(v);
        return *this;
    }

private:
    std::atomic<bool> flag_;
};

// ==================== Socket RAII Wrapper ====================
class Socket
{
public:
    Socket() : fd_(-1) {}
    explicit Socket(int fd) : fd_(fd) {}

    ~Socket() { close(); }

    Socket(Socket &&o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Socket &operator=(Socket &&o) noexcept
    {
        if (this != &o)
        {
            close();
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }

    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    int fd() const { return fd_; }
    bool valid() const { return fd_ >= 0; }

    void reset(int fd = -1)
    {
        close();
        fd_ = fd;
    }

    int release()
    {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void close()
    {
        int fd = fd_;
        fd_ = -1;
        if (fd >= 0)
        {
            ::shutdown(fd, SHUT_RDWR);
            while (::close(fd) < 0 && errno == EINTR)
            {
            }
        }
    }

    static Socket create_udp()
    {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0)
            set_cloexec(fd);
        return Socket(fd);
    }

    static Socket create_tcp()
    {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0)
            set_cloexec(fd);
        return Socket(fd);
    }

private:
    int fd_;

    static void set_cloexec(int fd)
    {
        int flags = fcntl(fd, F_GETFD);
        if (flags >= 0)
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
};

// ==================== Global Variables ====================
SafeFlag g_running(true);
std::atomic<uint64_t> g_total_bytes_in{0};
std::atomic<uint64_t> g_total_bytes_out{0};
std::string g_working_dir;
std::string g_exe_path;

// ==================== Get Absolute Path ====================
std::string get_absolute_path(const std::string &path)
{
    if (path.empty() || path[0] == '/')
        return path;
    if (!g_working_dir.empty())
        return g_working_dir + "/" + path;
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
        return std::string(cwd) + "/" + path;
    return path;
}

// ==================== JSON Parser ====================
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

    JsonValue() = default;
    JsonValue(bool v) : type(BOOL), bool_val(v) {}
    JsonValue(double v) : type(NUMBER), num_val(v) {}
    JsonValue(int v) : type(NUMBER), num_val(v) {}
    JsonValue(const std::string &v) : type(STRING), str_val(v) {}

    bool as_bool(bool def = false) const { return type == BOOL ? bool_val : def; }
    int as_int(int def = 0) const { return type == NUMBER ? (int)num_val : def; }
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

    const JsonValue &operator[](size_t idx) const
    {
        static JsonValue null_val;
        return (type == ARRAY && idx < arr_val.size()) ? arr_val[idx] : null_val;
    }

    size_t size() const
    {
        if (type == ARRAY)
            return arr_val.size();
        if (type == OBJECT)
            return obj_val.size();
        return 0;
    }

    bool has(const std::string &key) const
    {
        return type == OBJECT && obj_val.count(key) > 0;
    }

    bool is_array() const { return type == ARRAY; }
};

class JsonParser
{
public:
    static JsonValue parse_file(const std::string &filename)
    {
        std::ifstream file(filename);
        if (!file)
            throw std::runtime_error("Cannot open: " + filename);
        std::ostringstream ss;
        ss << file.rdbuf();
        size_t pos = 0;
        return parse_value(ss.str(), pos);
    }

private:
    static void skip_ws(const std::string &s, size_t &p)
    {
        while (p < s.size() && std::isspace((unsigned char)s[p]))
            p++;
    }

    static JsonValue parse_value(const std::string &s, size_t &p)
    {
        skip_ws(s, p);
        if (p >= s.size())
            return {};
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
            return {};
        }
        if (c == '-' || std::isdigit((unsigned char)c))
            return parse_number(s, p);
        return {};
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
            if (p >= s.size() || s[p] != '"')
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
        JsonValue v;
        v.type = JsonValue::STRING;
        v.str_val = r;
        return v;
    }

    static JsonValue parse_number(const std::string &s, size_t &p)
    {
        size_t start = p;
        if (s[p] == '-')
            p++;
        while (p < s.size() && std::isdigit((unsigned char)s[p]))
            p++;
        if (p < s.size() && s[p] == '.')
        {
            p++;
            while (p < s.size() && std::isdigit((unsigned char)s[p]))
                p++;
        }
        JsonValue v;
        v.type = JsonValue::NUMBER;
        v.num_val = std::stod(s.substr(start, p - start));
        return v;
    }

    static JsonValue parse_bool(const std::string &s, size_t &p)
    {
        if (s.compare(p, 4, "true") == 0)
        {
            p += 4;
            return JsonValue(true);
        }
        if (s.compare(p, 5, "false") == 0)
        {
            p += 5;
            return JsonValue(false);
        }
        return {};
    }
};

// ==================== Forward Rule ====================
struct ForwardRule
{
    std::string name;
    std::string listen_host = "0.0.0.0";
    int listen_port = 54321;
    std::string target_host = "127.0.0.1";
    int target_port = 19132;

    std::atomic<int> sessions{0};
    std::atomic<uint64_t> bytes_in{0};
    std::atomic<uint64_t> bytes_out{0};

    ForwardRule() = default;
    ForwardRule(const ForwardRule &o)
        : name(o.name), listen_host(o.listen_host), listen_port(o.listen_port),
          target_host(o.target_host), target_port(o.target_port) {}
};

// ==================== Configuration ====================
class Config
{
public:
    std::vector<ForwardRule> forwards;
    bool enable_tcp = false;
    bool enable_udp = true;
    int buffer_size = 65535;
    int udp_timeout = 120;
    int dns_refresh_interval = 3600;
    int max_sessions = 100;
    std::string log_level = "INFO";
    std::string log_file = "forward.log";
    bool log_to_file = true;
    bool log_to_console = true;
    bool daemon_mode = false;
    std::string pid_file = "mcbe_forward.pid";
    std::string work_dir;

    std::string abs_log_file;
    std::string abs_pid_file;
    std::string abs_config_file;

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
            abs_config_file = get_absolute_path(filename);
            JsonValue json = JsonParser::parse_file(filename);

            if (json.has("forwards") && json["forwards"].is_array())
            {
                for (size_t i = 0; i < json["forwards"].size(); i++)
                {
                    const auto &f = json["forwards"][i];
                    ForwardRule rule;
                    rule.name = f["name"].as_string("Forward" + std::to_string(i + 1));
                    rule.listen_host = f["listen_host"].as_string("0.0.0.0");
                    rule.listen_port = f["listen_port"].as_int(54321 + (int)i);
                    rule.target_host = f["target_host"].as_string("127.0.0.1");
                    rule.target_port = f["target_port"].as_int(19132);
                    forwards.push_back(rule);
                }
            }

            if (forwards.empty())
            {
                ForwardRule rule;
                rule.name = "Default";
                forwards.push_back(rule);
            }

            enable_tcp = json["enable_tcp"].as_bool(false);
            enable_udp = json["enable_udp"].as_bool(true);
            buffer_size = std::clamp(json["buffer_size"].as_int(65535), 1024, 1048576);
            udp_timeout = std::clamp(json["udp_timeout"].as_int(120), 10, 3600);
            dns_refresh_interval = std::clamp(json["dns_refresh_interval"].as_int(3600), 60, 86400);
            max_sessions = std::clamp(json["max_sessions"].as_int(100), 1, 10000);
            log_level = json["log_level"].as_string("INFO");
            log_file = json["log_file"].as_string("forward.log");
            log_to_file = json["log_to_file"].as_bool(true);
            log_to_console = json["log_to_console"].as_bool(true);
            daemon_mode = json["daemon_mode"].as_bool(false);
            pid_file = json["pid_file"].as_string("mcbe_forward.pid");
            work_dir = json["work_dir"].as_string("");

            abs_log_file = get_absolute_path(log_file);
            abs_pid_file = get_absolute_path(pid_file);

            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] Config: " << e.what() << std::endl;
            return false;
        }
    }

    void create_default(const std::string &filename)
    {
        std::ofstream file(filename);
        if (!file)
            return;
        file << R"({
    "forwards": [
        {
            "name": "Server1",
            "listen_port": 54321,
            "target_host": "127.0.0.1",
            "target_port": 19132
        }
    ],
    "enable_udp": true,
    "enable_tcp": false,
    "buffer_size": 65535,
    "udp_timeout": 120,
    "dns_refresh_interval": 3600,
    "max_sessions": 100,
    "log_level": "INFO"
})";
    }

    void print() const
    {
        std::cout << "\n+==================== CONFIG ====================+\n";
        std::cout << "| UDP: " << (enable_udp ? "ON" : "OFF");
        std::cout << " | TCP: " << (enable_tcp ? "ON" : "OFF");
        std::cout << " | Timeout: " << udp_timeout << "s";
        std::cout << " | Max: " << max_sessions << "\n";
        std::cout << "+------------------------------------------------+\n";
        for (const auto &f : forwards)
        {
            std::cout << "| [" << f.name << "] :" << f.listen_port
                      << " -> " << f.target_host << ":" << f.target_port << "\n";
        }
        std::cout << "+================================================+\n";
    }
};

Config g_config;

// ==================== Logger (Thread-Safe) ====================
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
        filename_ = filename;

        if (to_file_ && !filename_.empty())
        {
            file_.open(filename_, std::ios::app);
            if (!file_)
                to_file_ = false;
        }
    }

    void reopen()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open())
            file_.close();
        if (to_file_ && !filename_.empty())
        {
            file_.open(filename_, std::ios::app);
            if (!file_)
                to_file_ = false;
        }
    }

    void close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file_.is_open())
            file_.close();
    }

    void log(LogLevel level, const std::string &msg) noexcept
    {
        if (level < level_)
            return;

        try
        {
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch()) %
                      1000;

            char ts[32];
            struct tm tm_buf;
            localtime_r(&time_t_now, &tm_buf);
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

            static const char *prefix[] = {"[DEBUG]", "[INFO] ", "[WARN] ", "[ERROR]"};

            std::ostringstream ss;
            ss << ts << "." << std::setfill('0') << std::setw(3) << ms.count()
               << " " << prefix[level] << " " << msg;

            std::lock_guard<std::mutex> lock(mutex_);

            if (to_console_)
            {
                std::cout << ss.str() << std::endl;
            }

            if (to_file_ && file_.is_open())
            {
                file_ << ss.str() << std::endl;
                file_.flush();
            }
        }
        catch (...)
        {
            // Never throw from logger
        }
    }

    static void debug(const std::string &m) { instance().log(LOG_DEBUG, m); }
    static void info(const std::string &m) { instance().log(LOG_INFO, m); }
    static void warn(const std::string &m) { instance().log(LOG_WARN, m); }
    static void error(const std::string &m) { instance().log(LOG_ERROR, m); }

private:
    Logger() = default;
    ~Logger() { close(); }

    std::mutex mutex_;
    std::ofstream file_;
    std::string filename_;
    LogLevel level_ = LOG_INFO;
    bool to_file_ = false;
    bool to_console_ = true;
};

// ==================== DNS Resolver ====================
class DnsResolver
{
public:
    DnsResolver() = default;
    ~DnsResolver() { stop(); }

    bool init(const std::string &host, int port, const std::string &name)
    {
        hostname_ = host;
        port_ = port;
        name_ = name;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        {
            is_domain_ = false;
            std::lock_guard<std::shared_mutex> lock(mutex_);
            current_ip_ = host;
            target_addr_ = addr;
            return true;
        }

        is_domain_ = true;
        return resolve_now();
    }

    void start()
    {
        if (!is_domain_)
            return;

        running_ = true;
        thread_ = std::thread([this]
                              {
            try {
                int elapsed = 0;
                while (running_.get() && g_running.get()) {
                    for (int i = 0; i < 10 && running_.get() && g_running.get(); i++) {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }
                    if (!running_.get() || !g_running.get()) break;
                    
                    elapsed += 10;
                    if (elapsed >= g_config.dns_refresh_interval) {
                        elapsed = 0;
                        resolve_now();
                    }
                }
            } catch (...) {
                Logger::error("[" + name_ + "] DNS thread exception");
            } });
    }

    void stop()
    {
        running_ = false;
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    sockaddr_in get_target_addr() const
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return target_addr_;
    }

    std::string get_current_ip() const
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return current_ip_;
    }

    bool is_domain() const { return is_domain_; }
    const std::string &get_hostname() const { return hostname_; }

private:
    bool resolve_now() noexcept
    {
        try
        {
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            int ret = getaddrinfo(hostname_.c_str(), nullptr, &hints, &res);
            if (ret != 0 || !res)
            {
                Logger::error("[" + name_ + "] DNS failed: " + hostname_);
                return false;
            }

            auto *addr_in = reinterpret_cast<sockaddr_in *>(res->ai_addr);
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr_in->sin_addr, ip_buf, sizeof(ip_buf));
            std::string new_ip = ip_buf;

            {
                std::lock_guard<std::shared_mutex> lock(mutex_);
                bool changed = (!current_ip_.empty() && current_ip_ != new_ip);
                current_ip_ = new_ip;
                target_addr_.sin_family = AF_INET;
                target_addr_.sin_port = htons(port_);
                target_addr_.sin_addr = addr_in->sin_addr;

                if (changed)
                {
                    Logger::info("[" + name_ + "] DNS: " + hostname_ + " -> " + new_ip);
                }
            }

            freeaddrinfo(res);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    std::string hostname_, name_, current_ip_;
    int port_ = 0;
    sockaddr_in target_addr_{};
    mutable std::shared_mutex mutex_;
    SafeFlag running_{false};
    bool is_domain_ = false;
    std::thread thread_;
};

// ==================== Utility Functions ====================
void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::string addr_to_string(const sockaddr_in &addr)
{
    char buf[64];
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    snprintf(buf, sizeof(buf), "%s:%d", ip, ntohs(addr.sin_port));
    return buf;
}

std::string format_bytes(uint64_t bytes)
{
    static const char *units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 3)
    {
        size /= 1024;
        unit++;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f%s", size, units[unit]);
    return buf;
}

bool resolve_host(const std::string &host, sockaddr_in &addr)
{
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        return true;

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res)
    {
        addr.sin_addr = reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr;
        freeaddrinfo(res);
        return true;
    }
    return false;
}

// Safe write to pipe/signal
static int g_signal_pipe[2] = {-1, -1};

void signal_handler(int sig)
{
    if (sig == SIGHUP)
    {
        // Reopen log - safe in signal handler via pipe
        char c = 'R';
        ssize_t ret;
        do
        {
            ret = write(g_signal_pipe[1], &c, 1);
        } while (ret < 0 && errno == EINTR);
        return;
    }

    // Shutdown signal
    char c = 'Q';
    ssize_t ret;
    do
    {
        ret = write(g_signal_pipe[1], &c, 1);
    } while (ret < 0 && errno == EINTR);
}

void setup_signal_pipe()
{
    if (pipe(g_signal_pipe) < 0)
    {
        throw std::runtime_error("pipe() failed");
    }

    // Non-blocking write end
    fcntl(g_signal_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(g_signal_pipe[1], F_SETFL, O_NONBLOCK);
    fcntl(g_signal_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(g_signal_pipe[1], F_SETFD, FD_CLOEXEC);
}

void process_signals()
{
    char buf[16];
    ssize_t n;
    while ((n = read(g_signal_pipe[0], buf, sizeof(buf))) > 0)
    {
        for (ssize_t i = 0; i < n; i++)
        {
            if (buf[i] == 'R')
            {
                Logger::instance().reopen();
                Logger::info("Log reopened");
            }
            else if (buf[i] == 'Q')
            {
                g_running = false;
            }
        }
    }
}

// ==================== Daemonize ====================
bool increase_fd_limit()
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        rl.rlim_cur = std::min(rl.rlim_max, (rlim_t)65535);
        setrlimit(RLIMIT_NOFILE, &rl);
        return true;
    }
    return false;
}

bool daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid > 0)
    {
        int status;
        waitpid(pid, &status, 0);
        exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }

    if (setsid() < 0)
        _exit(1);

    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, nullptr);

    pid = fork();
    if (pid < 0)
        _exit(1);
    if (pid > 0)
    {
        std::cout << "Daemon PID: " << pid << std::endl;
        _exit(0);
    }

    umask(022);

    if (!g_config.work_dir.empty())
    {
        if (chdir(g_config.work_dir.c_str()) < 0)
        {
            if (!g_working_dir.empty())
                chdir(g_working_dir.c_str());
        }
    }
    else if (!g_working_dir.empty())
    {
        chdir(g_working_dir.c_str());
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0)
    {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO)
            close(fd);
    }

    increase_fd_limit();

    return true;
}

bool write_pid_file(const std::string &f)
{
    std::ofstream file(f);
    if (!file)
        return false;
    file << getpid();
    return true;
}

void remove_pid_file(const std::string &f) { unlink(f.c_str()); }

bool is_already_running(const std::string &pf)
{
    std::ifstream file(pf);
    if (!file)
        return false;
    pid_t pid;
    file >> pid;
    if (pid <= 0)
        return false;
    if (kill(pid, 0) == 0)
        return true;
    unlink(pf.c_str());
    return false;
}

void generate_service_file()
{
    std::ofstream file("ip_forward.service");
    if (!file)
        return;
    file << "[Unit]\nDescription=IP Forward v" VERSION "\nAfter=network.target\n\n"
         << "[Service]\nType=forking\nPIDFile=" << g_config.abs_pid_file << "\n"
         << "ExecStart=" << g_exe_path << " -c " << g_config.abs_config_file << " -d\n"
         << "ExecReload=/bin/kill -HUP $MAINPID\n"
         << "Restart=always\nRestartSec=5\nLimitNOFILE=65535\n\n"
         << "[Install]\nWantedBy=multi-user.target\n";
    std::cout << "Generated: ip_forward.service\n";
}

// ==================== Thread Pool ====================
class ThreadPool
{
public:
    explicit ThreadPool(size_t n) : stop_(false)
    {
        for (size_t i = 0; i < n; ++i)
        {
            workers_.emplace_back([this]
                                  {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mtx_);
                        cv_.wait(lk, [this] { return stop_ || !queue_.empty(); });
                        if (stop_ && queue_.empty()) return;
                        task = std::move(queue_.front());
                        queue_.pop();
                    }
                    try { if (task) task(); } catch (...) {}
                } });
        }
    }

    ~ThreadPool()
    {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto &w : workers_)
        {
            if (w.joinable())
                w.join();
        }
    }

    template <class F>
    void enqueue(F &&f)
    {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (stop_)
                return;
            queue_.emplace(std::forward<F>(f));
        }
        cv_.notify_one();
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> queue_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_;
};

// ==================== UDP Session ====================
struct UdpSession
{
    Socket server_socket;
    sockaddr_in client_addr{};
    std::string connected_ip;
    std::chrono::steady_clock::time_point last_active;

    UdpSession() { touch(); }
    void touch() { last_active = std::chrono::steady_clock::now(); }

    int idle_secs() const
    {
        return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::steady_clock::now() - last_active)
                                    .count());
    }
};

// ==================== UDP Forwarder (Using poll instead of select) ====================
class UdpForwarder
{
public:
    explicit UdpForwarder(ForwardRule &r) : rule_(r) {}
    ~UdpForwarder() { stop(); }

    bool start()
    {
        if (!dns_.init(rule_.target_host, rule_.target_port, rule_.name))
        {
            Logger::error("[" + rule_.name + "] DNS init failed");
            return false;
        }

        listen_socket_ = Socket::create_udp();
        if (!listen_socket_.valid())
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        int opt = 1;
        setsockopt(listen_socket_.fd(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_socket_.fd(), SOL_SOCKET, SO_RCVBUF,
                   &g_config.buffer_size, sizeof(g_config.buffer_size));
        setsockopt(listen_socket_.fd(), SOL_SOCKET, SO_SNDBUF,
                   &g_config.buffer_size, sizeof(g_config.buffer_size));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rule_.listen_port);
        if (!resolve_host(rule_.listen_host, addr))
        {
            Logger::error("[" + rule_.name + "] Cannot resolve: " + rule_.listen_host);
            return false;
        }

        if (bind(listen_socket_.fd(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            Logger::error("[" + rule_.name + "] bind() failed: " + std::string(strerror(errno)));
            return false;
        }

        set_nonblocking(listen_socket_.fd());
        running_ = true;
        dns_.start();

        fwd_thread_ = std::thread([this]
                                  {
            try { forward_loop(); }
            catch (const std::exception& e) {
                Logger::error("[" + rule_.name + "] Forward thread: " + e.what());
            }
            catch (...) {
                Logger::error("[" + rule_.name + "] Forward thread crashed");
            } });

        cleanup_thread_ = std::thread([this]
                                      {
            try { cleanup_loop(); }
            catch (...) {} });

        std::string tgt = rule_.target_host;
        if (dns_.is_domain())
            tgt += " (" + dns_.get_current_ip() + ")";
        Logger::info("[" + rule_.name + "] UDP :" + std::to_string(rule_.listen_port) + " -> " + tgt);

        return true;
    }

    void stop()
    {
        running_ = false;
        dns_.stop();
        listen_socket_.close();

        if (fwd_thread_.joinable())
            fwd_thread_.join();
        if (cleanup_thread_.joinable())
            cleanup_thread_.join();

        {
            std::lock_guard<std::mutex> lk(sess_mtx_);
            sessions_.clear();
            rule_.sessions = 0;
        }

        Logger::info("[" + rule_.name + "] UDP stopped");
    }

    const DnsResolver &dns() const { return dns_; }

private:
    ForwardRule &rule_;
    DnsResolver dns_;
    Socket listen_socket_;
    SafeFlag running_{false};
    std::thread fwd_thread_;
    std::thread cleanup_thread_;
    std::mutex sess_mtx_;
    std::map<std::string, std::unique_ptr<UdpSession>> sessions_;

    struct SessionInfo
    {
        int server_fd = -1;
        sockaddr_in client_addr{};
        std::string key;
    };

    SessionInfo get_or_create_session(const sockaddr_in &client)
    {
        std::string key = addr_to_string(client);
        SessionInfo info;
        info.key = key;
        info.client_addr = client;

        std::lock_guard<std::mutex> lk(sess_mtx_);

        auto it = sessions_.find(key);
        if (it != sessions_.end() && it->second && it->second->server_socket.valid())
        {
            info.server_fd = it->second->server_socket.fd();
            return info;
        }

        if (static_cast<int>(sessions_.size()) >= g_config.max_sessions)
        {
            Logger::warn("[" + rule_.name + "] Max sessions");
            return info;
        }

        auto sess = std::make_unique<UdpSession>();
        sess->client_addr = client;
        sess->connected_ip = dns_.get_current_ip();

        sess->server_socket = Socket::create_udp();
        if (!sess->server_socket.valid())
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return info;
        }

        sockaddr_in target = dns_.get_target_addr();
        if (connect(sess->server_socket.fd(),
                    reinterpret_cast<sockaddr *>(&target), sizeof(target)) < 0)
        {
            Logger::error("[" + rule_.name + "] connect() failed");
            return info;
        }

        set_nonblocking(sess->server_socket.fd());
        info.server_fd = sess->server_socket.fd();

        sessions_[key] = std::move(sess);
        rule_.sessions++;

        Logger::info("[" + rule_.name + "] New: " + key +
                     " (online: " + std::to_string(sessions_.size()) + ")");

        return info;
    }

    void touch_session(const std::string &key)
    {
        std::lock_guard<std::mutex> lk(sess_mtx_);
        auto it = sessions_.find(key);
        if (it != sessions_.end() && it->second)
        {
            it->second->touch();
        }
    }

    void forward_loop()
    {
        std::vector<char> buffer(g_config.buffer_size);
        std::vector<pollfd> pfds;
        pfds.reserve(g_config.max_sessions + 1);

        // Map from fd to session key
        std::map<int, std::string> fd_to_key;
        std::map<int, sockaddr_in> fd_to_client;

        while (running_.get() && g_running.get())
        {
            if (!listen_socket_.valid())
                break;

            pfds.clear();
            fd_to_key.clear();
            fd_to_client.clear();

            // Add listen socket
            pfds.push_back({listen_socket_.fd(), POLLIN, 0});

            // Add session sockets
            {
                std::lock_guard<std::mutex> lk(sess_mtx_);
                for (const auto &[key, sess] : sessions_)
                {
                    if (sess && sess->server_socket.valid())
                    {
                        int fd = sess->server_socket.fd();
                        pfds.push_back({fd, POLLIN, 0});
                        fd_to_key[fd] = key;
                        fd_to_client[fd] = sess->client_addr;
                    }
                }
            }

            int ret = poll(pfds.data(), pfds.size(), 100);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // Process listen socket
            if (pfds[0].revents & POLLIN)
            {
                sockaddr_in client{};
                socklen_t len = sizeof(client);
                ssize_t n = recvfrom(listen_socket_.fd(), buffer.data(), buffer.size(),
                                     0, reinterpret_cast<sockaddr *>(&client), &len);
                if (n > 0)
                {
                    g_total_bytes_in += n;
                    rule_.bytes_in += n;

                    SessionInfo sess = get_or_create_session(client);
                    if (sess.server_fd >= 0)
                    {
                        ssize_t sent;
                        do
                        {
                            sent = send(sess.server_fd, buffer.data(), n, 0);
                        } while (sent < 0 && errno == EINTR);

                        if (sent > 0)
                        {
                            g_total_bytes_out += sent;
                            rule_.bytes_out += sent;
                            touch_session(sess.key);
                        }
                    }
                }
            }

            // Process session sockets
            for (size_t i = 1; i < pfds.size(); i++)
            {
                if (!(pfds[i].revents & POLLIN))
                    continue;

                int fd = pfds[i].fd;
                auto key_it = fd_to_key.find(fd);
                auto client_it = fd_to_client.find(fd);
                if (key_it == fd_to_key.end() || client_it == fd_to_client.end())
                    continue;

                ssize_t n;
                do
                {
                    n = recv(fd, buffer.data(), buffer.size(), 0);
                } while (n < 0 && errno == EINTR);

                if (n > 0)
                {
                    g_total_bytes_in += n;
                    rule_.bytes_in += n;

                    if (listen_socket_.valid())
                    {
                        ssize_t sent;
                        do
                        {
                            sent = sendto(listen_socket_.fd(), buffer.data(), n, 0,
                                          reinterpret_cast<const sockaddr *>(&client_it->second),
                                          sizeof(client_it->second));
                        } while (sent < 0 && errno == EINTR);

                        if (sent > 0)
                        {
                            g_total_bytes_out += sent;
                            rule_.bytes_out += sent;
                            touch_session(key_it->second);
                        }
                    }
                }
            }
        }
    }

    void cleanup_loop()
    {
        while (running_.get() && g_running.get())
        {
            for (int i = 0; i < 5 && running_.get() && g_running.get(); i++)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!running_.get() || !g_running.get())
                break;

            std::vector<std::string> expired;

            {
                std::lock_guard<std::mutex> lk(sess_mtx_);
                for (const auto &[key, sess] : sessions_)
                {
                    if (sess && sess->idle_secs() > g_config.udp_timeout)
                    {
                        expired.push_back(key);
                    }
                }

                for (const auto &key : expired)
                {
                    Logger::info("[" + rule_.name + "] Timeout: " + key);
                    sessions_.erase(key);
                    rule_.sessions--;
                }
            }
        }
    }
};

// ==================== TCP Connection ====================
class TcpConnection : public std::enable_shared_from_this<TcpConnection>
{
public:
    TcpConnection(Socket client, const sockaddr_in &addr, ForwardRule &r, DnsResolver &d)
        : client_socket_(std::move(client)), client_addr_(addr), rule_(r), dns_(d) {}

    ~TcpConnection() { stop(); }

    bool start()
    {
        server_socket_ = Socket::create_tcp();
        if (!server_socket_.valid())
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        sockaddr_in target = dns_.get_target_addr();
        connected_ip_ = dns_.get_current_ip();

        // Set connect timeout
        struct timeval tv{10, 0};
        setsockopt(server_socket_.fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(server_socket_.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int ret;
        do
        {
            ret = connect(server_socket_.fd(),
                          reinterpret_cast<sockaddr *>(&target), sizeof(target));
        } while (ret < 0 && errno == EINTR);

        if (ret < 0)
        {
            Logger::error("[" + rule_.name + "] connect() failed: " + connected_ip_);
            return false;
        }

        running_ = true;
        rule_.sessions++;
        Logger::info("[" + rule_.name + "] TCP: " + addr_to_string(client_addr_) +
                     " -> " + connected_ip_);
        return true;
    }

    void run()
    {
        std::vector<char> buf(g_config.buffer_size);
        pollfd pfds[2];

        while (running_.get() && g_running.get())
        {
            if (!client_socket_.valid() || !server_socket_.valid())
                break;

            pfds[0] = {client_socket_.fd(), POLLIN, 0};
            pfds[1] = {server_socket_.fd(), POLLIN, 0};

            int ret = poll(pfds, 2, 1000);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (ret == 0)
                continue;

            // Client -> Server
            if (pfds[0].revents & (POLLIN | POLLERR | POLLHUP))
            {
                ssize_t n;
                do
                {
                    n = recv(client_socket_.fd(), buf.data(), buf.size(), 0);
                } while (n < 0 && errno == EINTR);

                if (n <= 0)
                    break;

                g_total_bytes_in += n;
                rule_.bytes_in += n;

                ssize_t sent;
                do
                {
                    sent = send(server_socket_.fd(), buf.data(), n, 0);
                } while (sent < 0 && errno == EINTR);

                if (sent <= 0)
                    break;

                g_total_bytes_out += sent;
                rule_.bytes_out += sent;
            }

            // Server -> Client
            if (pfds[1].revents & (POLLIN | POLLERR | POLLHUP))
            {
                ssize_t n;
                do
                {
                    n = recv(server_socket_.fd(), buf.data(), buf.size(), 0);
                } while (n < 0 && errno == EINTR);

                if (n <= 0)
                    break;

                g_total_bytes_in += n;
                rule_.bytes_in += n;

                ssize_t sent;
                do
                {
                    sent = send(client_socket_.fd(), buf.data(), n, 0);
                } while (sent < 0 && errno == EINTR);

                if (sent <= 0)
                    break;

                g_total_bytes_out += sent;
                rule_.bytes_out += sent;
            }
        }

        stop();
    }

    void stop()
    {
        if (!running_.exchange(false))
            return;
        client_socket_.close();
        server_socket_.close();
        rule_.sessions--;
        Logger::info("[" + rule_.name + "] TCP closed: " + addr_to_string(client_addr_));
    }

private:
    Socket client_socket_;
    Socket server_socket_;
    sockaddr_in client_addr_;
    ForwardRule &rule_;
    DnsResolver &dns_;
    std::string connected_ip_;
    SafeFlag running_{false};
};

// ==================== TCP Forwarder ====================
class TcpForwarder
{
public:
    explicit TcpForwarder(ForwardRule &r) : rule_(r), pool_(4) {}
    ~TcpForwarder() { stop(); }

    bool start()
    {
        if (!dns_.init(rule_.target_host, rule_.target_port, rule_.name))
        {
            Logger::error("[" + rule_.name + "] DNS init failed");
            return false;
        }

        listen_socket_ = Socket::create_tcp();
        if (!listen_socket_.valid())
        {
            Logger::error("[" + rule_.name + "] socket() failed");
            return false;
        }

        int opt = 1;
        setsockopt(listen_socket_.fd(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rule_.listen_port);
        if (!resolve_host(rule_.listen_host, addr))
        {
            Logger::error("[" + rule_.name + "] Cannot resolve listen host");
            return false;
        }

        if (bind(listen_socket_.fd(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            Logger::error("[" + rule_.name + "] bind() failed");
            return false;
        }

        if (listen(listen_socket_.fd(), 128) < 0)
        {
            Logger::error("[" + rule_.name + "] listen() failed");
            return false;
        }

        set_nonblocking(listen_socket_.fd());
        running_ = true;
        dns_.start();

        accept_thread_ = std::thread([this]
                                     {
            try { accept_loop(); }
            catch (...) {} });

        cleanup_thread_ = std::thread([this]
                                      {
            try { cleanup_loop(); }
            catch (...) {} });

        Logger::info("[" + rule_.name + "] TCP :" + std::to_string(rule_.listen_port));
        return true;
    }

    void stop()
    {
        running_ = false;
        dns_.stop();
        listen_socket_.close();

        if (accept_thread_.joinable())
            accept_thread_.join();
        if (cleanup_thread_.joinable())
            cleanup_thread_.join();

        {
            std::lock_guard<std::mutex> lk(conns_mtx_);
            for (auto &wp : connections_)
            {
                if (auto sp = wp.lock())
                    sp->stop();
            }
            connections_.clear();
        }

        Logger::info("[" + rule_.name + "] TCP stopped");
    }

private:
    ForwardRule &rule_;
    DnsResolver dns_;
    Socket listen_socket_;
    SafeFlag running_{false};
    std::thread accept_thread_;
    std::thread cleanup_thread_;
    ThreadPool pool_;
    std::mutex conns_mtx_;
    std::vector<std::weak_ptr<TcpConnection>> connections_;

    void accept_loop()
    {
        pollfd pfd{listen_socket_.fd(), POLLIN, 0};

        while (running_.get() && g_running.get())
        {
            if (!listen_socket_.valid())
                break;

            int ret = poll(&pfd, 1, 1000);
            if (ret <= 0)
                continue;

            sockaddr_in client{};
            socklen_t len = sizeof(client);

            int cfd;
            do
            {
                cfd = accept(listen_socket_.fd(), reinterpret_cast<sockaddr *>(&client), &len);
            } while (cfd < 0 && errno == EINTR);

            if (cfd < 0)
                continue;

            if (rule_.sessions >= g_config.max_sessions)
            {
                Logger::warn("[" + rule_.name + "] Max sessions");
                close(cfd);
                continue;
            }

            Socket client_sock(cfd);
            auto conn = std::make_shared<TcpConnection>(std::move(client_sock), client, rule_, dns_);

            if (conn->start())
            {
                {
                    std::lock_guard<std::mutex> lk(conns_mtx_);
                    connections_.push_back(conn);
                }
                pool_.enqueue([conn]
                              { conn->run(); });
            }
        }
    }

    void cleanup_loop()
    {
        while (running_.get() && g_running.get())
        {
            for (int i = 0; i < 10 && running_.get() && g_running.get(); i++)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (!running_.get() || !g_running.get())
                break;

            std::lock_guard<std::mutex> lk(conns_mtx_);
            connections_.erase(
                std::remove_if(connections_.begin(), connections_.end(),
                               [](const auto &wp)
                               { return wp.expired(); }),
                connections_.end());
        }
    }
};

// ==================== Forward Manager ====================
class ForwardManager
{
public:
    bool start()
    {
        for (auto &r : g_config.forwards)
        {
            if (g_config.enable_udp)
            {
                auto f = std::make_unique<UdpForwarder>(r);
                if (!f->start())
                    return false;
                udp_.push_back(std::move(f));
            }
            if (g_config.enable_tcp)
            {
                auto f = std::make_unique<TcpForwarder>(r);
                if (!f->start())
                    return false;
                tcp_.push_back(std::move(f));
            }
        }
        return true;
    }

    void stop()
    {
        for (auto &f : udp_)
            if (f)
                f->stop();
        for (auto &f : tcp_)
            if (f)
                f->stop();
        udp_.clear();
        tcp_.clear();
    }

    void print_status()
    {
        std::ostringstream ss;
        ss << "=== Status ===\n";

        int total = 0;
        for (const auto &r : g_config.forwards)
        {
            int s = r.sessions.load();
            total += s;
            ss << "[" << r.name << "] " << s << " sess | "
               << format_bytes(r.bytes_in.load()) << " in | "
               << format_bytes(r.bytes_out.load()) << " out";

            for (const auto &u : udp_)
            {
                if (u && u->dns().get_hostname() == r.target_host && u->dns().is_domain())
                {
                    ss << " | " << u->dns().get_current_ip();
                    break;
                }
            }
            ss << "\n";
        }

        ss << "Total: " << total << " | "
           << format_bytes(g_total_bytes_in.load()) << " in | "
           << format_bytes(g_total_bytes_out.load()) << " out";

        Logger::info(ss.str());
    }

private:
    std::vector<std::unique_ptr<UdpForwarder>> udp_;
    std::vector<std::unique_ptr<TcpForwarder>> tcp_;
};

// ==================== Main Loop ====================
void main_loop(ForwardManager &mgr)
{
    auto last_status = std::chrono::steady_clock::now();

    while (g_running.get())
    {
        // Process signals via pipe
        process_signals();

        // Status report every 60 seconds
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_status).count() >= 60)
        {
            last_status = now;
            mgr.print_status();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
 |___|_|     |_|  \___/|_|    \_/\_/ \__,_|_|  \__,_|  v)" VERSION "\n"
              << std::endl;
}

void print_usage(const char *p)
{
    std::cout << "Usage: " << p << " [options]\n"
              << "  -c <file>  Config file\n"
              << "  -d         Daemon mode\n"
              << "  -s         Stop daemon\n"
              << "  -g         Generate systemd service\n"
              << "  -h         Help\n";
}

int main(int argc, char *argv[])
{
    // Save paths before anything
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)))
        g_working_dir = cwd;

    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0)
    {
        exe[len] = '\0';
        g_exe_path = exe;
    }

    std::string config_file = "config.json";
    bool daemon = false, gen_svc = false, stop = false;

    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if (a == "-c" && i + 1 < argc)
            config_file = argv[++i];
        else if (a == "-d")
            daemon = true;
        else if (a == "-g")
            gen_svc = true;
        else if (a == "-s")
            stop = true;
        else if (a == "-h")
        {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Load config
    {
        std::ifstream chk(config_file);
        if (!chk.good())
        {
            std::cout << "Creating default config\n";
            g_config.create_default(config_file);
        }
    }

    if (!g_config.load(config_file))
    {
        std::cerr << "Failed to load config\n";
        return 1;
    }

    // Stop command
    if (stop)
    {
        if (is_already_running(g_config.abs_pid_file))
        {
            std::ifstream pf(g_config.abs_pid_file);
            pid_t pid;
            pf >> pid;
            std::cout << "Stopping " << pid << "...\n";
            kill(pid, SIGTERM);
            for (int i = 0; i < 50; i++)
            {
                usleep(100000);
                if (kill(pid, 0) != 0)
                {
                    std::cout << "Stopped\n";
                    return 0;
                }
            }
            std::cout << "Force kill\n";
            kill(pid, SIGKILL);
        }
        else
        {
            std::cout << "Not running\n";
        }
        return 0;
    }

    // Generate service
    if (gen_svc)
    {
        print_banner();
        generate_service_file();
        return 0;
    }

    // Check already running
    if (is_already_running(g_config.abs_pid_file))
    {
        std::cerr << "Already running\n";
        return 1;
    }

    print_banner();

    // Setup signal pipe
    try
    {
        setup_signal_pipe();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Signal pipe failed: " << e.what() << "\n";
        return 1;
    }

    // Daemonize
    if (daemon || g_config.daemon_mode)
    {
        std::cout << "Starting daemon...\n";
        if (!daemonize())
        {
            std::cerr << "Daemonize failed\n";
            return 1;
        }

        Logger::instance().init(g_config.abs_log_file, g_config.log_to_file,
                                false, g_config.get_log_level());
        write_pid_file(g_config.abs_pid_file);
        Logger::info("IP Forward v" VERSION " started (PID: " + std::to_string(getpid()) + ")");
    }
    else
    {
        g_config.print();
        Logger::instance().init(g_config.abs_log_file, g_config.log_to_file,
                                g_config.log_to_console, g_config.get_log_level());
    }

    // Signal handlers
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    signal(SIGPIPE, SIG_IGN);

    // Start forwarders
    ForwardManager mgr;
    if (!mgr.start())
    {
        Logger::error("Failed to start");
        remove_pid_file(g_config.abs_pid_file);
        return 1;
    }

    Logger::info("All forwards started");

    // Main loop
    main_loop(mgr);

    Logger::info("Shutting down...");
    mgr.stop();

    Logger::info("Bytes: " + format_bytes(g_total_bytes_in.load()) + " in / " +
                 format_bytes(g_total_bytes_out.load()) + " out");
    Logger::info("Goodbye!");

    Logger::instance().close();
    remove_pid_file(g_config.abs_pid_file);

    if (g_signal_pipe[0] >= 0)
        close(g_signal_pipe[0]);
    if (g_signal_pipe[1] >= 0)
        close(g_signal_pipe[1]);

    return 0;
}