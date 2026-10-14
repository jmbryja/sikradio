#include <unistd.h>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal>
#include <vector>
#include <poll.h>
#include <map>

using std::string;

const string HTTP_DEFAULT_PORT = "80";
const string HTTPS_DEFAULT_PORT = "443";
const int MAX_REDIRECTS = 10;

std::map<string, string> cookies;

struct Config {
    string url;
    bool multiplex = false;
    int timeout_ms = 5000;  // Poll timeout in ms.
    bool force_ipv4 = false;
    bool force_ipv6 = false;
    int verbosity = 2;
};

// Represents a url broken down to its components.
struct ParsedUrl {
    bool is_https = false;
    string host;
    string port;
    string path;
};
// Wraps socket and SSL context state for a single connection.
struct Connection {
    int sock_fd = -1;
    SSL *ssl = nullptr;
    SSL_CTX *ssl_ctx = nullptr;
    bool is_https = false;

};
// Stores relevant data extracted from the HTTP response headers.
struct ResponseInfo {
    string status_code;
    int icymetaint = 0; // Interval of audio bytes between metadata blocks.
    string redirect_url = "";
};

// Parses command line arguments using getopt.
// Returns true on success, false on invalid/missing arguments.
bool parse_arguments(int argc, char* argv[], Config &config) {
    int opt;
    while ((opt = getopt(argc, argv, "u:mt:46v:q")) != -1) {
        switch (opt) {
            case 'u':
                config.url = optarg;
                break;
            case 'm':
                config.multiplex = true;
                break;
            case 't':
                try {config.timeout_ms = std::stoi(optarg);}
                catch (...) {
                    std::cerr << "Error: Invalid timeout value.\n";
                    return false;
                }
                if (config.timeout_ms < 100 || config.timeout_ms > 100000) {
                    std::cerr << "Error: Timeout out of range.\n";
                    return false;
                }
                break;
            case '4':
                config.force_ipv4 = true;
                break;
            case '6':
                config.force_ipv6 = true;
                break;
            case 'v':
                try {config.verbosity = std::stoi(optarg);}
                catch (...) {
                    std::cerr << "Error: Invalid verbosity value.\n";
                    return false;
                }
                if (config.verbosity < 0 || config.verbosity > 4) {
                    std::cerr << "Error: Verbosity out of range.\n";
                    return false;
                }
                break;
            case 'q':
                config.verbosity = 0;
                break;
            default:
                return false;
        }
    }

    if (config.url.empty()) {
        std::cerr << "Error: Missing mandatory -u (URL) parameter.\n";
        return false;
    }

    return true;
}

// Manually parses a URL string into protocol, host, port, and path components.
bool parse_url(const string& url, ParsedUrl &parsed) {
    parsed.is_https = false;
    parsed.host.clear();
    parsed.port.clear();
    parsed.path.clear();
    auto it = url.find("://");
    if (it == string::npos) {
        std::cerr << "Error: Faulty URL parameter given.\n";
        return false;
    }
    // Extract the protocol.
    string prefix = url.substr(0, it);
    if (prefix == "http") {
        parsed.is_https = false;
        parsed.port = HTTP_DEFAULT_PORT;
    }
    else if (prefix == "https") {
        parsed.is_https = true;
        parsed.port = HTTPS_DEFAULT_PORT;
    }
    else {
        std::cerr << "Error: Faulty URL parameter given.\n";
        return false;
    }

    // Strip the url from the protocol.
    std::string stripped_url = url.substr(it + 3);
    it = stripped_url.find('/');
    string host_and_port;
    if (it != string::npos) {
        host_and_port = stripped_url.substr(0, it);
        parsed.path = stripped_url.substr(it);
    } else {
        host_and_port = stripped_url;
        parsed.path = "/";
    }
    // Extract host and port, handling IPv6 bracket notation (e.g., [::1]:8080).
    if (!host_and_port.empty() && host_and_port[0] == '[') {
        auto close_bracket = host_and_port.find(']');
        if (close_bracket == string::npos) {
            std::cerr << "Error: Faulty URL parameter given.\n";
            return false;
        }
        parsed.host = host_and_port.substr(1, close_bracket - 1);
        if (close_bracket + 1 < host_and_port.size() &&
            host_and_port[close_bracket + 1] == ':') {
            parsed.port = host_and_port.substr(close_bracket + 2);
            }
    }
    else {
        it = host_and_port.find(':');
        if (it != string::npos) {
            parsed.host = host_and_port.substr(0, it);
            parsed.port = host_and_port.substr(it + 1);
        }
        else {
            parsed.host = host_and_port;
        }
    }
    return true;
}
// Closes sockets and frees OpenSSL resources.
void cleanup(int sock_fd, SSL *ssl, SSL_CTX *ssl_ctx) {
    close(sock_fd);
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
    }
}

// Print timestamp in format YYYY.MM.DD HH.MM.SS
void print_timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm *time_info = std::localtime(&now);
    char buf[30];
    if (std::strftime(buf, sizeof(buf), "%Y.%m.%d %H.%M.%S",
        time_info) == 0) {
        std::cerr << "strftime failed\n";
        return;
    }
    std::cerr << buf << "\n";
}

// Reads from the socket/SSL connection one character at a time until a newline (\n).
// Strips carriage returns (\r) to cleanly handle HTTP header lines.
string read_line(int sock_fd, SSL* ssl, bool is_https, bool &got_eof) {
    string line;
    char c;
    got_eof = false;
    while (true) {
        ssize_t res;
        if (is_https)
            res = SSL_read(ssl, &c, 1);
        else
            res = read(sock_fd, &c, 1);
        if (res <= 0) {
            got_eof = true;
            return line;
        }
        if (c == '\n')
            break;
        if (c != '\r')
            line += c;
    }
    return line;
}

// Ensures all bytes in the buffer are written to the file descriptor (e.g., STDOUT).
// Handles partial writes which can occur with standard POSIX write().
bool write_all(int fd, const char* buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, buf + written, len - written);
        if (w < 0)
            return false;
        written += w;
    }
    return true;
}

// Ensures exactly 'len' bytes are read from the connection into the buffer.
// Crucial for reading exact audio chunk sizes based on icy-metaint.
bool read_exactly(Connection &conn, char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t r;
        if (conn.is_https)
            r = SSL_read(conn.ssl, buf + got, static_cast<int>(len - got));
        else
            r = read(conn.sock_fd, buf + got, len - got);
        if (r <= 0)
            return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

// Reads standard input to check if the user typed "quit\n".
// Maintains an accumulator to catch the string even if read in fragments.
bool check_stdin(string &acc, bool &stdin_open) {
    char buf[256];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) {
        stdin_open = false;
        return false;
    }
    acc.append(buf, static_cast<size_t>(n));
    if (acc.find("quit\n") != string::npos)
        return true;
    if (acc.size() > 4)
        acc = acc.substr(acc.size() - 4);
    return false;
}

// Tries to connect to the given URL and perform the HTTP request.
// Returns true on success, false on failure.
// Function always calls cleanup() on failure.
bool connect_and_request(const ParsedUrl &url, const Config &config,
    Connection &conn, ResponseInfo &resp) {
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    if (config.force_ipv4 && config.force_ipv6)
        hints.ai_family = AF_UNSPEC;
    else if (config.force_ipv4)
        hints.ai_family = AF_INET;
    else if (config.force_ipv6)
        hints.ai_family = AF_INET6;
    else
        hints.ai_family = AF_UNSPEC;

    if (config.verbosity >= 1) {
        std::cerr << "resolving name " << url.host << "\n";
    }

    int status = getaddrinfo(url.host.c_str(),
        url.port.c_str(), &hints, &result);
    if (status != 0) {
        if (config.verbosity >= 2) {
            std::cerr << "Error: getaddrinfo failed - " <<
                gai_strerror(status) << "\n";
        }
        return false;
    }

    conn.is_https = url.is_https;
    struct addrinfo *rp;

    // Iterating over addrinfo list.
    for (rp = result; rp != nullptr; rp = rp->ai_next) {

        // Logging connection info (when verbosity >= 1)
        if (config.verbosity >= 1) {
            print_timestamp();

            char host_buf[NI_MAXHOST];
            char serv_buf[NI_MAXSERV];

            // Convert address structure to text (IP and port)
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen, host_buf,
                sizeof(host_buf), serv_buf, sizeof(serv_buf),
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0) {

                if (rp->ai_family == AF_INET6) {
                    std::cerr << "connecting to server [" << host_buf << "]:"
                    << serv_buf << "\n";
                } else {
                    std::cerr << "connecting to server " << host_buf << ":"
                    << serv_buf << "\n";
                }
            }
        }

        // Creating a scoket.
        conn.sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (conn.sock_fd == -1) {
            continue;
        }


        // Trying to connect.
        if (connect(conn.sock_fd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break;
        }
        // Attempt to connect failed, closing the socket.
        close(conn.sock_fd);
        conn.sock_fd = -1;
    }

    freeaddrinfo(result);

    // Check if a connection was established.
    if (conn.sock_fd == -1) {
        if (config.verbosity >= 2) {
            std::cerr << "Error: Critical error - connection failed.\n";
        }
        return false;
    }

    if (config.verbosity >= 4) {
        std::cerr << "[DEBUG] Connected successfully. Socket FD: "
        << conn.sock_fd << "\n";
    }

    // Setting a timeout
    struct timeval tv;
    tv.tv_sec = config.timeout_ms / 1000;
    tv.tv_usec = (config.timeout_ms % 1000) * 1000;
    setsockopt(conn.sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


    if (url.is_https) {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        const SSL_METHOD *method = TLS_client_method();
        conn.ssl_ctx = SSL_CTX_new(method);

        if (!conn.ssl_ctx) {
            if (config.verbosity >= 2) {
                std::cerr << "Error: Critical error - "
                             "failed to create SSL context.\n";
            }
            close(conn.sock_fd);
            return false;
        }
        conn.ssl = SSL_new(conn.ssl_ctx);
        SSL_set_tlsext_host_name(conn.ssl, url.host.c_str());
        SSL_set_fd(conn.ssl, conn.sock_fd);

        // Perform the SSL/TLS handshake
        if (SSL_connect(conn.ssl) <= 0) {
            if (config.verbosity >= 2) {
                std::cerr << "Error: Critical error - SSL handshake failed.\n";
                ERR_print_errors_fp(stderr);
            }
            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
            return false;
        }
    }

    // Constructing the HTTP request.
    std::string request = "GET " + url.path + " HTTP/1.1\r\n";

    // ZAWSZE wysyłamy czysty host. Jeśli port jest standardowy (80/443), nie doklejamy go.
    if (url.host.find(':') != string::npos) {
        request += "Host: [" + url.host + "]\r\n";
    } else if (url.port != "80" && url.port != "443" && !url.port.empty()) {
        request += "Host: " + url.host + ":" + url.port + "\r\n";
    } else {
        request += "Host: " + url.host + "\r\n";
    }

    request += "Connection: Keep-Alive\r\n";

    // KLUCZOWE: Serwery komercyjne (jak Swiss Pop czy Capital) bez tego rzucają 404!
    request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n";

    if (!cookies.empty()) {
        request += "Cookie: ";
        bool first = true;
        for (const auto &kv : cookies) {
            if (!first)
                request += "; ";
            request += kv.first + "=" + kv.second;
            first = false;
        }
        request += "\r\n";
    }

    if (config.multiplex) {
        request += "Icy-MetaData: 1\r\n";
    }
    request += "\r\n";

    if (config.verbosity >= 1) {
        std::cerr << request;
    }

    ssize_t bytes_sent;
    if (url.is_https) {
        bytes_sent = SSL_write(conn.ssl, request.c_str(), request.length());
    } else {
        bytes_sent = write(conn.sock_fd, request.c_str(), request.length());
    }

    if (bytes_sent <= 0) {
        if (config.verbosity >= 2) {
            std::cerr << "Error: Critical error - "
                         "failed to send HTTP request.\n";
        }
        cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
        return false;
    }
    bool sl_eof = false;
    string status_line = read_line(conn.sock_fd, conn.ssl, url.is_https, sl_eof);
    if (config.verbosity >= 1) {
        std::cerr << status_line << "\n";
    }
    if (status_line.empty()) {
        if (config.verbosity >= 2) {
            std::cerr << "Error: Critical error - "
                         "failed to read HTTP response.\n";
        }
        cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
        return false;
    }
    const auto first_space = status_line.find(' ');
    if (first_space == string::npos) {
        if (config.verbosity >= 2) {
            std::cerr << "Error: Critical error - "
                         "invalid HTTP response format.\n";
        }
        cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
        return false;
    }
    resp.status_code = status_line.substr(first_space + 1, 3);
    while (true) {
        bool eof = false;
        string header = read_line(conn.sock_fd, conn.ssl, url.is_https, eof);
        if (eof) {
            if (config.verbosity >= 2)
                std::cerr << "Error: Connection closed during headers.\n";
            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
            return false;
        }
        if (header.empty())
            break;
        if (config.verbosity >= 1) {
            std::cerr << header << "\n";
        }
        auto colon = header.find(':');
        if (colon == string::npos)
            continue;

        string name = header.substr(0, colon);
        string value = header.substr(colon + 1);

        for (char &c : name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        size_t start = value.find_first_not_of(" \t");
        if (start != string::npos) {
            value = value.substr(start);
        }
        else
            value = "";
        if (name == "icy-metaint") {
            try { resp.icymetaint = std::stoi(value); }
            catch (...) {
                if (config.verbosity >= 2) {
                    std::cerr << "Error: Invalid ICY-METAINT value.\n";
                }
                cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                return false;
            }

        }
        else if (name == "location") {
            resp.redirect_url = value;
        }
        else if (name == "set-cookie") {
            string cookie = value;
            size_t semi = cookie.find(';');
            if (semi != string::npos)
                cookie = cookie.substr(0, semi);
            size_t eq = cookie.find('=');
            if (eq != string::npos)
                cookies[cookie.substr(0, eq)] = cookie.substr(eq + 1);
        }
    }
    return true;

}

int main(int argc, char *argv[]) {
    Config config;
    if (!parse_arguments(argc, argv, config)) {
        return 1;
    }

    // Print Debug info.
    if (config.verbosity >= 4) {
        std::cerr << "[DEBUG] URL: " << config.url << "\n";
        std::cerr << "[DEBUG] Multiplex: " << (config.multiplex ? "YES" : "NO") << "\n";
        std::cerr << "[DEBUG] Timeout: " << config.timeout_ms << " ms\n";
        std::cerr << "[DEBUG] IPv4: " << (config.force_ipv4 ? "YES" : "NO") << "\n";
        std::cerr << "[DEBUG] IPv6: " << (config.force_ipv6 ? "YES" : "NO") << "\n";
        std::cerr << "[DEBUG] Verbosity: " << config.verbosity << "\n";
    }
    ParsedUrl original_url;
    if (!parse_url(config.url, original_url)) {
        return 1;
    }
    ParsedUrl current_url = original_url;
    signal(SIGPIPE, SIG_IGN);
    string stdin_acc;
    bool stdin_open = true;
    int redirect_count = 0;
    while (true) {
        bool reconnect = false;
        Connection conn;
        ResponseInfo resp;
        if (!connect_and_request(current_url, config, conn, resp))
            return 1;

        if (resp.status_code == "200") {
            redirect_count = 0;
            struct pollfd fdsp[2];
            const size_t BUF_SIZE = 4096;
            char buf[BUF_SIZE];
            // There is metadata.
            if (resp.icymetaint > 0 && config.multiplex) {
                const int metaint = resp.icymetaint;
                std::vector<char> audio_buf(metaint);

                while (true) {
                    fdsp[0].fd = conn.sock_fd;
                    fdsp[0].events = POLLIN;
                    fdsp[1].fd = stdin_open ? STDIN_FILENO : -1;
                    fdsp[1].events = POLLIN;
                    int ret = poll(fdsp, 2, config.timeout_ms);
                    if (ret < 0) {
                        if (config.verbosity >= 2)
                            std::cerr << "Error: poll failed.\n";
                        cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                        return 1;
                    }
                    if (ret == 0) {
                        if (config.verbosity >= 1)
                            std::cerr << "data receiving timeout\n";
                        reconnect = true;
                        break;
                    }
                    if (fdsp[1].revents & POLLIN) {
                        if (stdin_open && (fdsp[1].revents & POLLIN)) {
                            if (check_stdin(stdin_acc, stdin_open)) {
                                cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                                return 0;
                            }
                        }
                    }
                    if (fdsp[0].revents & POLLIN) {
                        if (!read_exactly(conn, audio_buf.data(), metaint))
                            break;

                        if (!write_all(STDOUT_FILENO, audio_buf.data(), metaint))
                            break;
                        char len_byte;
                        if (!read_exactly(conn, &len_byte, 1))
                            break;
                        int meta_len = static_cast<unsigned char>(len_byte) * 16;
                        if (meta_len > 0) {
                            std::vector<char> meta_buf(meta_len);
                            if (!read_exactly(conn, meta_buf.data(), meta_len))
                                break;
                            string meta(meta_buf.data(), meta_len);
                            size_t zero = meta.find('\0');
                            if (zero != string::npos)
                                meta = meta.substr(0, zero);
                            meta += "\n";
                            if (!write_all(STDERR_FILENO, meta.data(), meta.size()))
                                break;
                        }
                    }
                }
                cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                if (reconnect) {
                    cookies.clear();
                    current_url = original_url;
                    redirect_count = 0;
                    continue;
                }
                return 0;
            }
            else {
                while (true) {
                    fdsp[0].fd = conn.sock_fd;
                    fdsp[0].events = POLLIN;
                    fdsp[1].fd = stdin_open ? STDIN_FILENO : -1;
                    fdsp[1].events = POLLIN;
                    int ret = poll(fdsp, 2, config.timeout_ms);
                    if (ret < 0) {
                        if (config.verbosity >= 2)
                            std::cerr << "Error: poll failed.\n";
                        cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                        return 1;
                    }
                    if (ret == 0) {
                        if (config.verbosity >= 1)
                            std::cerr << "data receiving timeout\n";
                        reconnect = true;
                        break;
                    }
                    if (fdsp[0].revents & POLLIN) {
                        ssize_t n;
                        if (conn.is_https)
                            n = SSL_read(conn.ssl, buf, BUF_SIZE);
                        else
                            n = read(conn.sock_fd, buf, BUF_SIZE);
                        if (n == 0)
                            break;
                        if (n < 0) {
                            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                            return 1;
                        }
                        if (!write_all(STDOUT_FILENO, buf, n))
                            break;
                    }
                    if (stdin_open && (fdsp[1].revents & (POLLIN | POLLHUP))) {
                        if (check_stdin(stdin_acc, stdin_open)) {
                            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                            return 0;
                        }
                    }
                }
                cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
                if (reconnect) {
                    cookies.clear();
                    current_url = original_url;
                    redirect_count = 0;
                    continue;
                }
                return 0;
            }
        }
        else if (!resp.status_code.empty() && resp.status_code[0] == '3') {
            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
            if (resp.redirect_url.empty()) {
                std::cerr << "Error: Redirect URL not found.\n";
                return 1;
            }
            if (++redirect_count >= MAX_REDIRECTS) {
                if (config.verbosity >= 2)
                    std::cerr << "Error: Too many redirects.\n";
                return 1;
            }
            if (!parse_url(resp.redirect_url, current_url)) {
                return 1;
            }
            // Tries to connect to the new url

            }
        else {
            if (config.verbosity >= 2) {
                std::cerr << "Error: HTTP response code: " << resp.status_code << "\n";
            }
            cleanup(conn.sock_fd, conn.ssl, conn.ssl_ctx);
            return 1;
        }
    }

}
