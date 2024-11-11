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
#include <fstream>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>

const int PORT = 8080;
const int BUFFER_SIZE = 1024;
const std::string DEFAULT_IP = "0.0.0.0";
const char* SESSION_FILE = "/tmp/chatV2_session";

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

struct SharedSessionData {
    pid_t server_pid;
    int active_connections;
    ConnectionStats stats[10]; 
    bool valid;
};

class NetworkMonitor {
private:
    std::map<int, ConnectionStats> connections;
    std::mutex statsMutex;
    bool isRunning;
    bool displayEnabled;
    std::thread monitorThread;
    int shmid;
    SharedSessionData* sharedData;
    std::chrono::system_clock::time_point startTime;

    void createSharedMemory() {
        key_t key = ftok(SESSION_FILE, 'R');
        shmid = shmget(key, sizeof(SharedSessionData), IPC_CREAT | 0666);
        if (shmid < 0) {
            throw std::runtime_error("Failed to create shared memory");
        }
        sharedData = (SharedSessionData*)shmat(shmid, nullptr, 0);
        if (sharedData == (void*)-1) {
            throw std::runtime_error("Failed to attach shared memory");
        }
    }

    std::string formatBytes(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB"};
        int unitIndex = 0;
        double size = bytes;
        
        while (size >= 1024 && unitIndex < 3) {
            size /= 1024;
            unitIndex++;
        }
        
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
        return ss.str();
    }

    std::string formatDuration(std::chrono::seconds duration) {
        auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        duration -= hours;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        duration -= minutes;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);

        std::stringstream ss;
        if (hours.count() > 0) {
            ss << hours.count() << "h ";
        }
        if (minutes.count() > 0 || hours.count() > 0) {
            ss << minutes.count() << "m ";
        }
        ss << seconds.count() << "s";
        return ss.str();
    }

public:
    NetworkMonitor() 
        : isRunning(false), 
          displayEnabled(false), 
          shmid(-1), 
          sharedData(nullptr) {
        startTime = std::chrono::system_clock::now();
        std::ofstream(SESSION_FILE).close();
    }

    void startMonitoring(bool showDisplay = false, bool attachMode = false) {
        isRunning = true;
        displayEnabled = showDisplay;

        if (attachMode) {
            try {
                createSharedMemory();
                if (!sharedData->valid) {
                    throw std::runtime_error("No active server session found");
                }
                std::cout << "Successfully attached to running server session\n";
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                isRunning = false;
                return;
            }
        }

        monitorThread = std::thread([this, attachMode]() {
            while (isRunning) {
                if (displayEnabled) {
                    if (attachMode) {
                        displaySharedStats();
                    } else {
                        displayStats();
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
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
        updateSharedMemory();
    }

    void removeConnection(int socket) {
        std::lock_guard<std::mutex> lock(statsMutex);
        connections.erase(socket);
        updateSharedMemory();
    }

    void displayStats() {
        std::lock_guard<std::mutex> lock(statsMutex);
        auto now = std::chrono::system_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - startTime);

        system("clear");  // Clear screen
        
        // Header
        std::cout << "\n╔════════════════════════════════════════════════════╗\n";
        std::cout << "║             Network Monitor Statistics              ║\n";
        std::cout << "╠════════════════════════════════════════════════════╣\n";
        
        // System Info
        std::cout << "║ Uptime: " << std::left << std::setw(41) << formatDuration(uptime) << "║\n";
        std::cout << "║ Active Connections: " << std::left << std::setw(33) << connections.size() << "║\n";
        
        // Connection Details
        if (!connections.empty()) {
            std::cout << "╠════════════════════════════════════════════════════╣\n";
            std::cout << "║                Connection Details                  ║\n";
            std::cout << "╠════════════════════════════════════════════════════╣\n";
            
            for (const auto& [socket, stats] : connections) {
                auto connDuration = std::chrono::duration_cast<std::chrono::seconds>(
                    now - stats.connectedTime);
                
                std::cout << "║ Socket: " << std::left << std::setw(42) << socket << "║\n";
                std::cout << "║ Address: " << std::left << std::setw(41) 
                          << (stats.peerAddress + ":" + std::to_string(stats.peerPort)) << "║\n";
                std::cout << "║ Duration: " << std::left << std::setw(40) 
                          << formatDuration(connDuration) << "║\n";
                std::cout << "║ Data Sent: " << std::left << std::setw(40) 
                          << formatBytes(stats.bytesSent) << "║\n";
                std::cout << "║ Data Received: " << std::left << std::setw(36) 
                          << formatBytes(stats.bytesReceived) << "║\n";
                std::cout << "║ Messages Sent: " << std::left << std::setw(37) 
                          << stats.messagesSent << "║\n";
                std::cout << "║ Messages Received: " << std::left << std::setw(33) 
                          << stats.messagesReceived << "║\n";
                
                // Add separator between connections
                if (std::next(connections.find(socket)) != connections.end()) {
                    std::cout << "╟────────────────────────────────────────────────────╢\n";
                }
            }
        }
        
        std::cout << "╚════════════════════════════════════════════════════╝\n";
    }

    void displaySharedStats() {
        if (!sharedData) return;

        auto now = std::chrono::system_clock::now();
        
        system("clear");
        std::cout << "\n╔════════════════════════════════════════════════════╗\n";
        std::cout << "║           Attached Monitor Statistics              ║\n";
        std::cout << "╠════════════════════════════════════════════════════╣\n";
        std::cout << "║ Server PID: " << std::left << std::setw(39) << sharedData->server_pid << "║\n";
        std::cout << "║ Active Connections: " << std::left << std::setw(33) 
                  << sharedData->active_connections << "║\n";

        if (sharedData->active_connections > 0) {
            std::cout << "╠════════════════════════════════════════════════════╣\n";
            std::cout << "║                Connection Details                  ║\n";
            std::cout << "╠════════════════════════════════════════════════════╣\n";

            for (int i = 0; i < sharedData->active_connections; i++) {
                const auto& stats = sharedData->stats[i];
                auto connDuration = std::chrono::duration_cast<std::chrono::seconds>(
                    now - stats.connectedTime);

                std::cout << "║ Connection " << (i + 1) << std::left << std::setw(39) << "║\n";
                std::cout << "║ Address: " << std::left << std::setw(41) 
                          << (stats.peerAddress + ":" + std::to_string(stats.peerPort)) << "║\n";
                std::cout << "║ Duration: " << std::left << std::setw(40) 
                          << formatDuration(connDuration) << "║\n";
                std::cout << "║ Data Sent: " << std::left << std::setw(40) 
                          << formatBytes(stats.bytesSent) << "║\n";
                std::cout << "║ Data Received: " << std::left << std::setw(36) 
                          << formatBytes(stats.bytesReceived) << "║\n";
                std::cout << "║ Messages Sent: " << std::left << std::setw(37) 
                          << stats.messagesSent << "║\n";
                std::cout << "║ Messages Received: " << std::left << std::setw(33) 
                          << stats.messagesReceived << "║\n";

                if (i < sharedData->active_connections - 1) {
                    std::cout << "╟────────────────────────────────────────────────────╢\n";
                }
            }
        }

        std::cout << "╚════════════════════════════════════════════════════╝\n";
    }

    void updateStats(int socket, size_t bytesSent, size_t bytesReceived, 
                    size_t msgSent = 0, size_t msgReceived = 0) {
        std::lock_guard<std::mutex> lock(statsMutex);
        if (connections.find(socket) != connections.end()) {
            connections[socket].bytesSent += bytesSent;
            connections[socket].bytesReceived += bytesReceived;
            connections[socket].messagesSent += msgSent;
            connections[socket].messagesReceived += msgReceived;
            updateSharedMemory();
        }
    }

    void updateSharedMemory() {
        if (!sharedData) return;

        sharedData->server_pid = getpid();
        sharedData->active_connections = connections.size();
        sharedData->valid = true;

        int i = 0;
        for (const auto& [socket, stats] : connections) {
            if (i >= 10) break;
            sharedData->stats[i] = stats;
            i++;
        }
    }

    ~NetworkMonitor() {
        stopMonitoring();
        if (sharedData) {
            shmdt(sharedData);
        }
        if (shmid >= 0) {
            shmctl(shmid, IPC_RMID, nullptr);
        }
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
    bool attachMode = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-s" || arg == "-c" || arg == "-m") {
            mode = arg;
        } else if (arg == "-a") {
            attachMode = true;
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
        std::cout << "As monitor: " << argv[0] << " -m [-a]\n";
        std::cout << "  -a: attach to running server session\n";
        return 1;
    }

    if (mode == "-m") {
        NetworkMonitor monitor;
        monitor.startMonitoring(true, attachMode);
        std::cout << "Press Enter to stop monitoring...\n";
        std::cin.get();
        return 0;
    }

    if (mode == "-s" && chatCode.empty()) {
        chatCode = generateRandomKey();
        std::cout << "Code: " << chatCode << std::endl;
    }

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
