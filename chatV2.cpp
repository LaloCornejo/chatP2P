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
#include <random>
#include <ctime>
#include <vector>
#include <map>
#include <chrono>

const int PORT = 8080;
const int BUFFER_SIZE = 1024;
const std::string DEFAULT_IP = "0.0.0.0";

std::string generateRandomKey(int length = 16) {
    const std::string charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.size() - 1);
    
    std::string randomKey;
    for (int i = 0; i < length; ++i) {
        randomKey += charset[distribution(generator)];
    }
    return randomKey;
}

std::string generateRandomUsername() {
    const std::vector<std::string> adjectives = {"Idiot", "Dumb", "Inbred", "Lazy", "Dogshit"};
    const std::vector<std::string> nouns = {"Panda", "Donkey", "Hamburger", "Spagetti", "Panino"};
    
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> adj_dist(0, adjectives.size() - 1);
    std::uniform_int_distribution<int> noun_dist(0, nouns.size() - 1);
    
    return adjectives[adj_dist(generator)] + nouns[noun_dist(generator)] + 
           std::to_string(generator() % 1000);
}

class ConnectionAnimator {
private:
    const std::vector<std::string> BRAILLE_FRAMES = {
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    };
    std::atomic<bool> running{false};
    std::thread animationThread;

public:
    void startAnimation() {
        running = true;
        animationThread = std::thread([this]() {
            int frame = 0;
            while (running) {
                std::cout << "\r" << BRAILLE_FRAMES[frame] << " Connecting to server..." << std::flush;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                frame = (frame + 1) % BRAILLE_FRAMES.size();
            }
            std::cout << "\r" << std::string(30, ' ') << "\r" << std::flush;
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

struct ConnectionStats {
  std::chrono::system_clock::time_point connectedTime;
  size_t bytesSent;
  size_t bytesReceived;
  size_t messagesSent;
  size_t messagesReceived;
  std::string peerAddress;
  int peerPort;

  ConnectionStats() : bytesSent(0), bytesReceived(0), messagesSent(0), messagesReceived(0), peerPort(0) {
    connectedTime = std::chrono::system_clock::now();
  }
};

class NetworkMonitor {
private:
    std::map<int, ConnectionStats> connections;
    std::mutex statsMutex;
    bool isRunning;
    bool displayEnabled;
    std::thread monitorThread;

public:
    NetworkMonitor() : isRunning(false), displayEnabled(false) {}

    void startMonitoring(bool showDisplay = false) {
        isRunning = true;
        displayEnabled = showDisplay;
        monitorThread = std::thread([this]() {
            while (isRunning) {
                if (displayEnabled) {
                    displayStats();
                }
                std::this_thread::sleep_for(std::chrono::seconds(3));
            }
        });
        monitorThread.detach();
    }

    void stopMonitoring() {
      isRunning = false;
      if (monitorThread.joinable()) {
        monitorThread.join();
      }
    }

    void addConnection(int socket, const std::string& address, int port) {
      std::lock_guard<std::mutex> lock(statsMutex);
      connections[socket] = ConnectionStats();
      connections[socket].peerAddress = address;
      connections[socket].peerPort = port;
    }

    void updateStats(int socket, size_t bytesSent, size_t bytesReceived, size_t msgSent = 0, size_t messagesReceived = 0) {
      std::lock_guard<std::mutex> lock(statsMutex);
      if(connections.find(socket) != connections.end()) {
        connections[socket].bytesSent += bytesSent;
        connections[socket].bytesReceived += bytesReceived;
        connections[socket].messagesSent += msgSent;
        connections[socket].messagesReceived += messagesReceived;
      }
    }

    void displayStats() {
      std::lock_guard<std::mutex> lock(statsMutex);
      system("clear");
      std::cout << "\n=== Network Monitor ===\n";
      for (const auto& [socket, stats] : connections) {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.connectedTime).count();

        std::cout << "\nConncetion " << socket << " (" << stats.peerAddress << ":" << stats.peerPort << ")\n";
        std::cout << "Connceted for: " << duration << " seconds\n";
        std::cout << "Bytes sent: " << stats.bytesSent << "\n";
        std::cout << "Bytes received: " << stats.bytesReceived << "\n";
        std::cout << "Messages sent: " << stats.messagesSent << "\n";
        std::cout << "Messages received: " << stats.messagesReceived << "\n";
      }
    
      std::cout << "\n=========================\n";
    }

    ~NetworkMonitor() {
      stopMonitoring();
    }
};

class P2PChat {
private:
    int serverSocket;
    int clientSocket;
    std::string chatCode;
    std::string username;
    MessageQueue messageQueue;
    NetworkMonitor monitor;
    bool isServer;
    std::thread heartbeatThread;
    bool running;

    void startHeartbeat() {
      std::thread([this]() {
          while(running) {
            std::string heartbeat = "/heartbeat";
            send(clientSocket, heartbeat.c_str(), heartbeat.length(), 0);
            std::this_thread::sleep_for(std::chrono::seconds(1));
          }
        }).detach();
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

    void setupServer() {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == -1) {
            throw std::runtime_error("Failed to create server socket");
        }

        struct sockaddr_in serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            throw std::runtime_error("Failed to bind server socket");
        }

        listen(serverSocket, 1);
    }

    void acceptConnection() {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        std::memset(&clientAddr, 0, sizeof(clientAddr));
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

        std::string receivedHash = std::string(buffer, bytesRead);
        if (receivedHash != chatCode) {
            close(clientSocket);
            throw std::runtime_error("Invalid chat code from client");
        }

        std::string sc = "/connected";
        send(clientSocket, sc.c_str(), sc.length(), 0);
        std::cout << "Valid code" << std::endl;
    }

        void connectToServer(const std::string& ip) {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == -1) {
            throw std::runtime_error("Failed to create client socket");
        }

        struct sockaddr_in serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(PORT);
        inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

        ConnectionAnimator animator;
        animator.startAnimation();

        if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            animator.stopAnimation();
            throw std::runtime_error("Failed to connect to server");
        } else {
            send(clientSocket, chatCode.c_str(), chatCode.length(), 0);

            std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();
            char buffer[BUFFER_SIZE];
            int await_time = 2;

            while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start).count() < await_time) {
                std::memset(buffer, 0, BUFFER_SIZE);
                ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
                if (bytesRead > 0) {
                    std::string receivedHash = std::string(buffer, bytesRead);
                    if (receivedHash == "/connected") {
                        animator.stopAnimation();
                        std::cout << "Authenticated" << std::endl;
                        return;
                    }
                }
            }

            animator.stopAnimation();
            throw std::runtime_error("Failed to receive response from server");
            close(clientSocket);
        }
    }

   void receiveMessages() {
        char buffer[BUFFER_SIZE];
        int missedHeartbeats = 0;
        const int MAX_MISSED_HEARTBEATS = 3;

        while (running) {
            std::memset(buffer, 0, BUFFER_SIZE);
            ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytesRead <= 0) {
                running = false;
                break;
            }

            std::string message = std::string(buffer, bytesRead);
            
            if (!isServer && message == "/heartbeat") {
                missedHeartbeats = 0;
                continue;
            }

            if (!isServer) {
                missedHeartbeats++;
                if (missedHeartbeats >= MAX_MISSED_HEARTBEATS) {
                    messageQueue.push("\nServer connection lost. Closing...");
                    running = false;
                    break;
                }
            }

            if (message != "/heartbeat") {
                messageQueue.push("\n" + message);
                monitor.updateStats(clientSocket, 0, bytesRead, 0, 1);
            }
        }
    }

    void sendMessages() {
        std::string input;
        send(clientSocket, chatCode.c_str(), chatCode.length(), 0);

        while (running) {
            std::getline(std::cin, input);
            if (input == "bye") {
                running = false;
                break;
            }
            std::string formattedMsg = username + ": " + input;
            send(clientSocket, formattedMsg.c_str(), formattedMsg.length(), 0);
            monitor.updateStats(clientSocket, formattedMsg.length(), 0, 1, 0);
    }
    }

    void displayMessages() {
        while (running) {
            std::string msg = messageQueue.pop();
            std::cout << msg << std::endl;
        }
    }

public:
    P2PChat(const std::string& code, const std::string& user = "", bool server = false) 
        : running(true), serverSocket(-1), clientSocket(-1), isServer(server) {
        chatCode = generateHash(code);
        username = user.empty() ? generateRandomUsername() : user;
    }

    
    void startServer() {
        setupServer();
        std::cout << "Username: " << username << std::endl;
        std::cout << "Waiting for connection..." << std::endl;
        acceptConnection();
        
        monitor.addConnection(clientSocket, "client", PORT);
        monitor.startMonitoring(false);
        
        startHeartbeat();

        std::thread receiveThread(std::bind(&P2PChat::receiveMessages, this));
        std::thread sendThread(std::bind(&P2PChat::sendMessages, this));
        std::thread displayThread(std::bind(&P2PChat::displayMessages, this));

        receiveThread.detach();
        sendThread.detach();
        displayThread.join();

        cleanup();
    }

    void startClient(const std::string& ip) {
        connectToServer(ip);
        std::cout << "Connected to server. Username: " << username << std::endl;

        std::thread receiveThread(std::bind(&P2PChat::receiveMessages, this));
        std::thread sendThread(std::bind(&P2PChat::sendMessages, this));
        std::thread displayThread(std::bind(&P2PChat::displayMessages, this));

        receiveThread.detach();
        sendThread.detach();
        displayThread.join();

        cleanup();
    }

    void cleanup() {
        if (clientSocket != -1) close(clientSocket);
        if (serverSocket != -1) close(serverSocket);
    }

    ~P2PChat() {
        cleanup();
    }
};

int main(int argc, char* argv[]) {
    std::string mode;
    std::string chatCode;
    std::string username;
    std::string serverIp = DEFAULT_IP;
    bool monitorMode = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-s" || arg == "-c" || arg == "-m") {
            mode = arg;
        } else if (arg == "-k" && i + 1 < argc) {
            chatCode = argv[++i];
        } else if (arg == "-u" && i + 1 < argc) {
            username = argv[++i];
        } else if (mode == "-c" && serverIp == DEFAULT_IP && arg.find(".") != std::string::npos) {
            serverIp = arg;
        }
    }

    if (mode.empty()) {
        std::cout << "Usage:\n";
        std::cout << "As server: " << argv[0] << " -s [-k <chat_code>] [-u <username>]\n";
        std::cout << "As client: " << argv[0] << " -c [server_ip] -k <chat_code> [-u <username>]\n";
        std::cout << "As monitor: " << argv[0] << " -m\n";
        return 1;
    }

        NetworkMonitor monitor;
        monitor.startMonitoring();
        std::cout << "Press Enter to stop monitoring...\n";
        std::cin.get();
        return 0;
    }

    if (mode == "-s" && chatCode.empty()) {
        chatCode = generateRandomKey();
        std::cout << "Code: " << chatCode << std::endl;
    }

    // Verify client has chat code
    if (mode == "-c" && chatCode.empty()) {
        std::cout << "Error: Chat code is required for client mode.\n";
        std::cout << "Use -k <chat_code> to specify the code.\n";
        return 1;
    }

    try {
        P2PChat chat(chatCode, username, mode == "-s");
        if (mode == "-s") {
            chat.startServer();
        } else if (mode == "-c") {
            chat.startClient(serverIp);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
