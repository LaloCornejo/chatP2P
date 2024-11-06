#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <cstring>
#include <system_error>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <cmath>
#include <sstream>
#include <atomic>
#include <deque>

// OpenSSL includes
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// ANSI escape codes for colors and cursor control
#define CLEAR "\033[2J\033[1;1H"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define RESET "\033[0m"

class SocketError : public std::runtime_error {
public:
    SocketError(const std::string& message) 
        : std::runtime_error(message + ": " + strerror(errno)) {}
};

class P2PChat {
private:
    int serverSocket;
    std::atomic<bool> isRunning;
    std::mutex consoleMutex;
    std::mutex peersMutex;
    std::string accessCode;
    struct sockaddr_in serverAddr;
    
    struct Peer {
        int socket;
        std::string address;
        std::chrono::system_clock::time_point connectTime;
        std::thread handler;
    };
    
    std::map<std::string, std::shared_ptr<Peer>> peers;
    
    EVP_CIPHER_CTX *encryptCtx;
    EVP_CIPHER_CTX *decryptCtx;
    unsigned char key[32];
    unsigned char iv[16];
    
    struct NetworkStats {
        std::atomic<size_t> bytesSent;
        std::atomic<size_t> bytesReceived;
        std::atomic<int> activeConnections;
        std::chrono::system_clock::time_point startTime;
    } stats;

    void initializeSocket(int port) {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            throw SocketError("Failed to create server socket");
        }

        // Set socket options
        int flags = fcntl(serverSocket, F_GETFL, 0);
        if (flags == -1) {
            close(serverSocket);
            throw SocketError("Failed to get socket flags");
        }
        
        if (fcntl(serverSocket, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(serverSocket);
            throw SocketError("Failed to set non-blocking mode");
        }

        int reuseAddr = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) == -1) {
            close(serverSocket);
            throw SocketError("Failed to set SO_REUSEADDR");
        }

        // Configure timeouts
        struct timeval timeout;      
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        
        if (setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
            std::cerr << "Warning: Failed to set receive timeout\n";
        }
        
        if (setsockopt(serverSocket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
            std::cerr << "Warning: Failed to set send timeout\n";
        }

        // Bind socket
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            close(serverSocket);
            throw SocketError("Failed to bind socket");
        }
    }

    void initializeEncryption() {
        if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
            throw std::runtime_error("Failed to generate random key/IV");
        }

        encryptCtx = EVP_CIPHER_CTX_new();
        if (!encryptCtx) {
            throw std::runtime_error("Failed to create encryption context");
        }

        decryptCtx = EVP_CIPHER_CTX_new();
        if (!decryptCtx) {
            EVP_CIPHER_CTX_free(encryptCtx);
            throw std::runtime_error("Failed to create decryption context");
        }
    }

    std::vector<unsigned char> encrypt(const std::string& plaintext) {
        std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
        int len1, len2;

        if (EVP_EncryptInit_ex(encryptCtx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            throw std::runtime_error("Failed to initialize encryption");
        }

        if (EVP_EncryptUpdate(encryptCtx, ciphertext.data(), &len1,
                            reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                            plaintext.length()) != 1) {
            throw std::runtime_error("Failed to encrypt data");
        }

        if (EVP_EncryptFinal_ex(encryptCtx, ciphertext.data() + len1, &len2) != 1) {
            throw std::runtime_error("Failed to finalize encryption");
        }

        ciphertext.resize(len1 + len2);
        return ciphertext;
    }

    std::string decrypt(const std::vector<unsigned char>& ciphertext) {
        std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int len1, len2;

        if (EVP_DecryptInit_ex(decryptCtx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            throw std::runtime_error("Failed to initialize decryption");
        }

        if (EVP_DecryptUpdate(decryptCtx, plaintext.data(), &len1,
                            ciphertext.data(), ciphertext.size()) != 1) {
            throw std::runtime_error("Failed to decrypt data");
        }

        if (EVP_DecryptFinal_ex(decryptCtx, plaintext.data() + len1, &len2) != 1) {
            throw std::runtime_error("Failed to finalize decryption");
        }

        return std::string(reinterpret_cast<char*>(plaintext.data()), len1 + len2);
    }

    void displayStats() {
        while (isRunning) {
            auto now = std::chrono::system_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                now - stats.startTime).count();
            
            {
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << CLEAR;
                std::cout << BLUE << "=== Network Statistics ===" << RESET << "\n";
                std::cout << "Uptime: " << uptime << " seconds\n";
                std::cout << "Bytes sent: " << stats.bytesSent << "\n";
                std::cout << "Bytes received: " << stats.bytesReceived << "\n";
                std::cout << "Active connections: " << stats.activeConnections << "\n\n";
                
                std::cout << "Connected Peers:\n";
                std::lock_guard<std::mutex> peersLock(peersMutex);
                for (const auto& [addr, peer] : peers) {
                    auto connectedTime = std::chrono::duration_cast<std::chrono::minutes>(
                        now - peer->connectTime).count();
                    std::cout << addr << " - Connected for " << connectedTime << " minutes\n";
                }
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    void handleClient(std::shared_ptr<Peer> peer) {
        std::vector<unsigned char> buffer(4096);
        
        // Authenticate peer
        ssize_t bytesRead = recv(peer->socket, buffer.data(), buffer.size(), 0);
        if (bytesRead <= 0) {
            removePeer(peer);
            return;
        }

        std::string receivedCode(reinterpret_cast<char*>(buffer.data()), bytesRead);
        if (receivedCode != accessCode) {
            std::string reject = "Invalid access code";
            send(peer->socket, reject.c_str(), reject.length(), 0);
            removePeer(peer);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(consoleMutex);
            std::cout << GREEN << "\nNew peer connected: " << peer->address << RESET << std::endl;
        }

        while (isRunning) {
            bytesRead = recv(peer->socket, buffer.data(), buffer.size(), 0);
            
            if (bytesRead <= 0) {
                break;
            }
            
            stats.bytesReceived += bytesRead;
            
            try {
                std::vector<unsigned char> encrypted(buffer.data(), buffer.data() + bytesRead);
                std::string decrypted = decrypt(encrypted);
                
                std::lock_guard<std::mutex> lock(consoleMutex);
                std::cout << BLUE << peer->address << ": " << RESET << decrypted << std::endl;
                
                // Broadcast to other peers
                broadcastMessage(decrypted, peer->address);
            } catch (const std::exception& e) {
                std::cerr << "Error processing message from " << peer->address 
                         << ": " << e.what() << std::endl;
            }
        }
        
        removePeer(peer);
    }

    void removePeer(std::shared_ptr<Peer> peer) {
        std::lock_guard<std::mutex> lock(peersMutex);
        close(peer->socket);
        peers.erase(peer->address);
        stats.activeConnections--;
    }

    void broadcastMessage(const std::string& message, const std::string& sender) {
        auto encrypted = encrypt(message);
        
        std::lock_guard<std::mutex> lock(peersMutex);
        for (const auto& [addr, peer] : peers) {
            if (addr != sender) {
                send(peer->socket, encrypted.data(), encrypted.size(), 0);
                stats.bytesSent += encrypted.size();
            }
        }
    }

public:
    P2PChat(int port, const std::string& code) 
        : isRunning(true), accessCode(code), encryptCtx(nullptr), decryptCtx(nullptr) {
        try {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
            initializeEncryption();
            initializeSocket(port);
            
            stats.bytesSent = 0;
            stats.bytesReceived = 0;
            stats.activeConnections = 0;
            stats.startTime = std::chrono::system_clock::now();
        } catch (...) {
            cleanup();
            throw;
        }
    }

    void start() {
        if (listen(serverSocket, SOMAXCONN) == -1) {
            throw SocketError("Failed to listen on socket");
        }

        std::cout << GREEN << "Server started successfully on port " 
                 << ntohs(serverAddr.sin_port) << RESET << "\n";

        std::thread(&P2PChat::displayStats, this).detach();

        while (isRunning) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

            if (clientSocket == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                std::cerr << "Warning: Failed to accept connection: " 
                         << strerror(errno) << std::endl;
                continue;
            }

            auto peer = std::make_shared<Peer>();
            peer->socket = clientSocket;
            peer->address = inet_ntoa(clientAddr.sin_addr);
            peer->connectTime = std::chrono::system_clock::now();
            
            {
                std::lock_guard<std::mutex> lock(peersMutex);
                peers[peer->address] = peer;
                stats.activeConnections++;
            }

            peer->handler = std::thread(&P2PChat::handleClient, this, peer);
            peer->handler.detach();
        }
    }

    void sendMessage(const std::string& message) {
        try {
            broadcastMessage(message, "server");
        } catch (const std::exception& e) {
            std::cerr << "Error sending message: " << e.what() << std::endl;
        }
    }

    void cleanup() {
        if (encryptCtx) {
            EVP_CIPHER_CTX_free(encryptCtx);
            encryptCtx = nullptr;
        }
        if (decryptCtx) {
            EVP_CIPHER_CTX_free(decryptCtx);
            decryptCtx = nullptr;
        }
        EVP_cleanup();
        ERR_free_strings();
        
        std::lock_guard<std::mutex> lock(peersMutex);
        for (auto& [addr, peer] : peers) {
            close(peer->socket);
        }
        peers.clear();
        
        close(serverSocket);
    }

    ~P2PChat() {
        isRunning = false;
        cleanup();
    }
};

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Shutting down...\n";
    exit(signum);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if (argc < 2) {
        std::cout << "Usage: ./p2p_chat [OPTIONS]\n"
                  << "Options:\n"
                  << "  -p, --port PORT       Port to use (default: 8080)\n"
                  << "  -c, --code CODE       Access code for the chat\n"
                  << "  -h, --host           Run as host\n"
                  << "  -j, --join IP        Join existing chat at IP address\n"
                  << "  --help               Show this help message\n";
        return 1;
    }

    int port = 8080;
    std::string accessCode;
    std::string hostIp;
    bool isHost = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
                if (port <= 0 || port > 65535) {
                    std::cerr << "Port must be between 1 and 65535\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Invalid port number\n";
                return 1;
            }
        } else if ((arg == "-c" || arg == "--code") && i + 1 < argc) {
            accessCode = argv[++i];
        } else if (arg == "-h" || arg == "--host") {
            isHost = true;
        } else if ((arg == "-j" || arg == "--join") && i + 1 < argc) {
            hostIp = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: ./p2p_chat [OPTIONS]\n"
                     << "Options:\n"
                     << "  -p, --port PORT       Port to use (default: 8080)\n"
                     << "  -c, --code CODE       Access code for the chat\n"
                     << "  -h, --host           Run as host\n"
                     << "  -j, --join IP        Join existing chat at IP address\n"
                     << "  --help               Show this help message\n";
            return 0;
        }
    }

    if (accessCode.empty()) {
        std::cerr << "Access code is required (-c or --code)\n";
        return 1;
    }

    if (!isHost && hostIp.empty()) {
        std::cerr << "Must specify either host (-h) or join (-j) mode\n";
        return 1;
    }

    try {
        if (isHost) {
            std::cout << GREEN << "Starting P2P chat server on port " << port << RESET << "\n";
            P2PChat chat(port, accessCode);
            
            // Start input handling thread
            std::thread inputThread([&chat]() {
                std::string input;
                while (std::getline(std::cin, input)) {
                    if (input == "/quit") {
                        break;
                    }
                    chat.sendMessage(input);
                }
            });

            // Start server
            chat.start();
            inputThread.join();
            
        } else {
            // Client mode
            int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket == -1) {
                throw SocketError("Failed to create client socket");
            }

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            
            if (inet_pton(AF_INET, hostIp.c_str(), &serverAddr.sin_addr) <= 0) {
                throw SocketError("Invalid address");
            }

            std::cout << YELLOW << "Connecting to " << hostIp << ":" << port << RESET << "\n";
            
            if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
                throw SocketError("Connection failed");
            }

            // Send access code
            if (send(clientSocket, accessCode.c_str(), accessCode.length(), 0) == -1) {
                throw SocketError("Failed to send access code");
            }

            // Start receive thread
            std::atomic<bool> running{true};
            std::thread receiveThread([clientSocket, &running]() {
                char buffer[4096];
                while (running) {
                    ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                    if (bytesRead <= 0) {
                        std::cout << RED << "\nDisconnected from server" << RESET << "\n";
                        running = false;
                        break;
                    }
                    buffer[bytesRead] = '\0';
                    std::cout << buffer << std::endl;
                }
            });

            // Handle user input
            std::string input;
            while (running && std::getline(std::cin, input)) {
                if (input == "/quit") {
                    break;
                }
                if (send(clientSocket, input.c_str(), input.length(), 0) == -1) {
                    std::cerr << "Failed to send message\n";
                    break;
                }
            }

            running = false;
            close(clientSocket);
            receiveThread.join();
        }
        
    } catch (const std::exception& e) {
        std::cerr << RED << "Error: " << e.what() << RESET << std::endl;
        return 1;
    }

    return 0;
}
