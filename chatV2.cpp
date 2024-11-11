#include <iostream>
#include <string>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <functional>
#include <netdb.h>
#include <poll.h>
#include <ifaddrs.h>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <random>

const int PORT = 8080;
const int BUFFER_SIZE = 1024;
const std::string DEFAULT_IP = "0.0.0.0";
const int RECONNECT_ATTEMPTS = 3;
const int RECONNECT_DELAY_MS = 2000;
const int HEARTBEAT_INTERVAL_MS = 5000;
const int STATUS_UPDATE_INTERVAL_MS = 1000;

struct NetworkStats {
    uint64_t bytesSent{0};
    uint64_t bytesReceived{0};
    std::chrono::system_clock::time_point lastHeartbeat;
    bool isConnected{false};
    int latency{0};
    std::string currentProtocol{"Unknown"};
};

struct UserContext {
    std::string username;
    bool isAuthenticated{false};
    std::chrono::system_clock::time_point lastActive;
};

class MessageQueue {
private:
    std::queue<std::string> messages;
    std::mutex mtx;
    std::condition_variable cv;

public:
    void push(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx);
        messages.push(msg);
        cv.notify_one();
    }

    std::string pop() {
        std::unique_lock<std::mutex> lock(mtx);
        while (messages.empty()) {
            cv.wait(lock);
        }
        std::string msg = messages.front();
        messages.pop();
        return msg;
    }
};

class ConnectionAnimator {
private:
    const std::vector<std::string> BRAILLE_FRAMES = {
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    };
    std::atomic<bool> running{false};
    std::thread animationThread;

public:
    void startAnimation(const std::string& message = "Connecting to server...") {
        running = true;
        animationThread = std::thread([this, message]() {
            int frame = 0;
            while (running) {
                std::cout << "\r" << BRAILLE_FRAMES[frame] << " " << message << std::flush;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                frame = (frame + 1) % BRAILLE_FRAMES.size();
            }
            std::cout << "\r" << std::string(50, ' ') << "\r" << std::flush;
        });
    }

    void stopAnimation() {
        running = false;
        if (animationThread.joinable()) {
            animationThread.join();
        }
    }

    ~ConnectionAnimator() {
        stopAnimation();
    }
};

class P2PChat {
private:
    int serverSocket;
    int clientSocket;
    std::string chatCode;
    std::string username;
    MessageQueue messageQueue;
    bool running;
    NetworkStats stats;
    UserContext userContext;
    ConnectionAnimator animator;

    std::string generateRandomCode(int length = 9) {
       const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, characters.length() - 1);
        
        std::string code;
        for (int i = 0; i < length; ++i) {
            code += characters[dis(gen)];
        }
        return code;
    }

    std::string generateHash(const std::string& input) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;

        EVP_MD_CTX* context = EVP_MD_CTX_new();
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
        EVP_DigestUpdate(context, input.c_str(), input.length());
        EVP_DigestFinal_ex(context, hash, &hashLen);
        EVP_MD_CTX_free(context);

        std::stringstream ss;
        for (unsigned int i = 0; i < hashLen; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    void setupDualStackServer() {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;     // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        int status = getaddrinfo(NULL, std::to_string(PORT).c_str(), &hints, &res);
        if (status != 0) {
            throw std::runtime_error("getaddrinfo error: " + std::string(gai_strerror(status)));
        }

        struct addrinfo *p;
        for(p = res; p != NULL; p = p->ai_next) {
            serverSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (serverSocket == -1) continue;

            int yes = 1;
            if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
                close(serverSocket);
                continue;
            }

            if (p->ai_family == AF_INET6) {
                if (setsockopt(serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) == -1) {
                    close(serverSocket);
                    continue;
                }
            }

            if (bind(serverSocket, p->ai_addr, p->ai_addrlen) == 0) {
                stats.currentProtocol = (p->ai_family == AF_INET6) ? "IPv6" : "IPv4";
                break;
            }

            close(serverSocket);
        }

        freeaddrinfo(res);

        if (p == NULL) {
            throw std::runtime_error("Failed to bind to any address");
        }

        if (listen(serverSocket, 5) == -1) {
            throw std::runtime_error("Listen failed");
        }
    }

    bool connectToDualStack(const std::string& host) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(host.c_str(), std::to_string(PORT).c_str(), &hints, &res);
        if (status != 0) {
            return false;
        }

        struct addrinfo *p;
        for(p = res; p != NULL; p = p->ai_next) {
            clientSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (clientSocket == -1) continue;

            if (connect(clientSocket, p->ai_addr, p->ai_addrlen) != -1) {
                stats.currentProtocol = (p->ai_family == AF_INET6) ? "IPv6" : "IPv4";
                break;
            }

            close(clientSocket);
        }

        freeaddrinfo(res);
        return (p != NULL);
    }

public:
    P2PChat(const std::string& username = "") 
        : running(true), serverSocket(-1), clientSocket(-1) {
        std::string randomCode = generateRandomCode();
        chatCode = generateHash(randomCode);
        
        this->username = username.empty() ? promptUsername() : username;
        userContext.username = this->username;
        userContext.isAuthenticated = false;
        userContext.lastActive = std::chrono::system_clock::now();
        stats.lastHeartbeat = std::chrono::system_clock::now();
        
        std::cout << "Kode: " << randomCode << std::endl;
    }

    std::string promptCode() {
        std::string code;
        do {
            std::cout << "Enter chat code: ";
            std::getline(std::cin, code);
            code = trim(code);
        } while (code.empty());
        return code;
    }

    std::string promptUsername() {
        std::string username;
        do {
            std::cout << "Enter your username: ";
            std::getline(std::cin, username);
            username = trim(username);
        } while (username.empty());
        return username;
    }

    static std::string trim(const std::string& str) {
        auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
        auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
        return (start < end ? std::string(start, end) : std::string());
    }

    void setupServer() {
        serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            throw std::runtime_error("Failed to create server socket");
        }

        int no = 0;
        if (setsockopt(serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0) {
            close(serverSocket);
            throw std::runtime_error("Failed to set IPv6 dual-stack option");
        }

        int yes = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            close(serverSocket);
            throw std::runtime_error("Failed to set socket reuse option");
        }

        struct sockaddr_in6 serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin6_family = AF_INET6;
        serverAddr.sin6_port = htons(PORT);
        serverAddr.sin6_addr = in6addr_any;

        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            close(serverSocket);
            throw std::runtime_error("Failed to bind server socket");
        }

        if (listen(serverSocket, 1) < 0) {
            close(serverSocket);
            throw std::runtime_error("Failed to listen on server socket");
        }
    }

    void acceptConnection() {
        struct sockaddr_storage clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket < 0) {
            throw std::runtime_error("Failed to accept connection");
        }

        char buffer[BUFFER_SIZE];
        std::memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesRead <= 0) {
            close(clientSocket);
            throw std::runtime_error("Failed to receive chat code from client");
        }

        std::string receivedMsg(buffer, bytesRead);
        std::cout << receivedMsg << std::endl;
        size_t delimPos = receivedMsg.find('|');
        if (delimPos == std::string::npos) {
            close(clientSocket);
            throw std::runtime_error("Invalid authentication message format");
        }

        std::string receivedHash = receivedMsg.substr(0, delimPos);
        std::string clientUsername = receivedMsg.substr(delimPos + 1);

        if (receivedHash != chatCode) {
            close(clientSocket);
            throw std::runtime_error("Invalid chat code from client");
        }

        messageQueue.push("\nUser " + clientUsername + " connected");
        std::string authMessage = "AUTH_OK|" + username;
        send(clientSocket, authMessage.c_str(), authMessage.length(), 0);
        stats.isConnected = true;
    }

    void connectToServer(const std::string& ip, const std::string& code) {
      std::string clientCode = code;
        std::cout <<  chatCode << std::endl;
        struct addrinfo hints, *servinfo, *p;
        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(ip.c_str(), std::to_string(PORT).c_str(), &hints, &servinfo);
        if (status != 0) {
            throw std::runtime_error("getaddrinfo error: " + std::string(gai_strerror(status)));
        }

        ConnectionAnimator animator;
        animator.startAnimation();

        for(p = servinfo; p != NULL; p = p->ai_next) {
            clientSocket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (clientSocket == -1) {
                continue;
            }

            if (connect(clientSocket, p->ai_addr, p->ai_addrlen) != -1) {
                break;  // Successfully connected
            }

            close(clientSocket);
        }

        freeaddrinfo(servinfo);

        if (p == NULL) {
            animator.stopAnimation();
            throw std::runtime_error("Failed to connect");
        }

        std::string authMessage = clientCode + "|" + username;
        send(clientSocket, authMessage.c_str(), authMessage.length(), 0);

        char buffer[BUFFER_SIZE];
        std::memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytesRead <= 0) {
            animator.stopAnimation();
            close(clientSocket);
            throw std::runtime_error("Failed to receive server response");
        }

        std::string response(buffer, bytesRead);
        size_t delimPos = response.find('|');
        if (delimPos == std::string::npos || response.substr(0, delimPos) != "AUTH_OK") {
            animator.stopAnimation();
            close(clientSocket);
            throw std::runtime_error("Authentication failed");
        }

        std::string serverUsername = response.substr(delimPos + 1);
        animator.stopAnimation();
        messageQueue.push("\nConnected to " + serverUsername + "'s chat");
        stats.isConnected = true;
    }

    void sendHeartbeat() {
        if (clientSocket != -1) {
            std::string heartbeat = "/heartbeat";
            auto start = std::chrono::high_resolution_clock::now();
            send(clientSocket, heartbeat.c_str(), heartbeat.length(), 0);
            stats.bytesSent += heartbeat.length();
            
            char buffer[BUFFER_SIZE];
            std::memset(buffer, 0, BUFFER_SIZE);
            if (recv(clientSocket, buffer, BUFFER_SIZE - 1, MSG_DONTWAIT) > 0) {
                auto end = std::chrono::high_resolution_clock::now();
                stats.latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                    end - start
                ).count();
            }
        }
    }

    bool attemptReconnection() {
        for (int attempt = 0; attempt < RECONNECT_ATTEMPTS; ++attempt) {
            std::cout << "\rAttempting reconnection (" << attempt + 1 << "/"
                      << RECONNECT_ATTEMPTS << ")..." << std::flush;
            
            if (clientSocket != -1) {
                close(clientSocket);
            }

            try {
                connectToServer(DEFAULT_IP, chatCode);
                std::cout << "\nReconnected successfully!" << std::endl;
                return true;
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(RECONNECT_DELAY_MS)
                );
            }
        }
        return false;
    }

    void monitorStatus() {
        while (running) {
            auto now = std::chrono::system_clock::now();
            auto heartbeatDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - stats.lastHeartbeat
            ).count();

            if (heartbeatDiff > HEARTBEAT_INTERVAL_MS) {
                sendHeartbeat();
                stats.lastHeartbeat = now;
            }

            if (heartbeatDiff > HEARTBEAT_INTERVAL_MS * 2) {
                if (stats.isConnected) {
                    stats.isConnected = false;
                    messageQueue.push("\nConnection lost. Attempting to reconnect...");
                    if (!attemptReconnection()) {
                        messageQueue.push("\nFailed to reconnect after multiple attempts.");
                        running = false;
                        break;
                    }
                }
            }

            std::cout << "\r[Status] Connected: " << (stats.isConnected ? "Yes" : "No")
                      << " | Latency: " << stats.latency << "ms"
                      << " | Bytes Sent: " << stats.bytesSent
                      << " | Bytes Received: " << stats.bytesReceived
                      << std::flush;

            std::this_thread::sleep_for(std::chrono::milliseconds(STATUS_UPDATE_INTERVAL_MS));
        }
    }

    void receiveMessages() {
      char buffer[BUFFER_SIZE];
      while (running) {
          std::memset(buffer, 0, BUFFER_SIZE);
          ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
          if (bytesRead <= 0) {
              if (running) {
                  stats.isConnected = false;
                  messageQueue.push("\nConnection lost");
              }
              running = false;
              break;
          }

          if (bytesRead > 0) {
              std::string message(buffer, std::min(bytesRead, static_cast<ssize_t>(BUFFER_SIZE - 1)));
              if (message == "/heartbeat") {
                  send(clientSocket, message.c_str(), message.length(), 0);
                  continue;
              }

              stats.bytesReceived += bytesRead;
              messageQueue.push("\nReceived: " + message);
          }
      }
    }

    void sendMessages() {
        std::string input;
        while (running) {
            std::getline(std::cin, input);
            if (input == "bye") {
                running = false;
                break;
            }

            std::string formattedMsg = username + ": " + input;
            send(clientSocket, formattedMsg.c_str(), formattedMsg.length(), 0);
            stats.bytesSent += formattedMsg.length();
        }
    }

    void displayMessages() {
        while (running) {
            std::string msg = messageQueue.pop();
            std::cout << msg << std::endl;
        }
    }

    void startServer() {
        setupServer();
        std::cout << "Waiting for connection...\n";
        acceptConnection();
        std::cout << "Client connected\n";

        std::thread receiveThread(&P2PChat::receiveMessages, this);
        std::thread sendThread(&P2PChat::sendMessages, this);
        std::thread displayThread(&P2PChat::displayMessages, this);
        std::thread monitorThread(&P2PChat::monitorStatus, this);

        receiveThread.detach();
        sendThread.detach();
        monitorThread.detach();
        displayThread.join();

        cleanup();
    }

    void startClient(const std::string& ip, const std::string& code) {
        connectToServer(ip, code);
        std::cout << "Connected to server\n";

        std::thread receiveThread(&P2PChat::receiveMessages, this);
        std::thread sendThread(&P2PChat::sendMessages, this);
        std::thread displayThread(&P2PChat::displayMessages, this);
        std::thread monitorThread(&P2PChat::monitorStatus, this);

        receiveThread.detach();
        sendThread.detach();
        monitorThread.detach();
        displayThread.join();

        cleanup();
    }

    void cleanup() {
        running = false;
        if (clientSocket != -1) {
            close(clientSocket);
            clientSocket = -1;
        }
        if (serverSocket != -1) {
            close(serverSocket);
            serverSocket = -1;
        }
    }

    ~P2PChat() {
        cleanup();
    }
};

int main(int argc, char* argv[]) {
    std::string username;
    std::string mode;
    std::string serverIP = DEFAULT_IP;
    std::string code;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-s" || arg == "-c") {
            mode = arg;
        }else if (arg == "-k" && i + 1 < argc) {
            code = argv[++i];
        } else if (arg == "-u" && i + 1 < argc) {
            username = argv[++i];
        } else if (arg == "-ip" && i + 1 < argc) {
            serverIP = argv[++i];
        }
    }

    if (mode.empty()) {
        std::cout << "Usage:\n"
                  << "As server: " << argv[0] << " -s [-u username]\n"
                  << "As client: " << argv[0] << " -c -ip <server_ip> [-u username]\n"
                  << "Options:\n"
                  << "  -u <username>   Set username\n"
                  << "  -ip <server_ip> Specify server IP (required for client mode)\n";
        return 1;
    }

    try {
        P2PChat chat(username);
        
        if (mode == "-s") {
            chat.startServer();
        } else if (mode == "-c") {
            if (serverIP == DEFAULT_IP) {
                std::cout << "Error: Server IP is required in client mode\n";
                return 1;
            }
            chat.startClient(serverIP, code);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
