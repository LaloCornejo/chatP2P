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
#include <atomic>

const int PORT = 8080;
const int BUFFER_SIZE = 1024;
const std::string DEFAULT_IP = "0.0.0.0";

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

class P2PChat {
private:
    int serverSocket;
    int clientSocket;
    std::string chatCode;
    MessageQueue messageQueue;
    bool running;

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
        std::cout << "Client connected with valid chat code" << std::endl;
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
            int await_time = 3;

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
        }
    }

    void receiveMessages() {
        char buffer[BUFFER_SIZE];
        while (running) {
            std::memset(buffer, 0, BUFFER_SIZE);
            ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
            if (bytesRead <= 0) {
                running = false;
                break;
            }
            std::string receivedHash = std::string(buffer, bytesRead);
            if (receivedHash == chatCode) {
                messageQueue.push("\nAuthenticated");
            } else {
                messageQueue.push("\nReceived: " + std::string(buffer));
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
            send(clientSocket, input.c_str(), input.length(), 0);
        }
    }

    void displayMessages() {
        while (running) {
            std::string msg = messageQueue.pop();
            std::cout << msg << std::endl;
        }
    }

public:
    P2PChat(const std::string& code) : running(true), serverSocket(-1), clientSocket(-1) {
        chatCode = generateHash(code);
    }

    void startServer() {
        setupServer();
        std::cout << "Waiting for connection...\n";
        acceptConnection();
        std::cout << "Client connected\n";

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
        std::cout << "Connected to server\n";

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
    if (argc < 3) {
        std::cout << "Usage:\n";
        std::cout << "As server: " << argv[0] << " -s <chat_code>\n";
        std::cout << "As client: " << argv[0] << " -c <chat_code> <server_ip>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string chatCode = argv[2];

    try {
        P2PChat chat(chatCode);
        if (mode == "-s") {
            chat.startServer();
        } else if (mode == "-c") {
            if (argc == 4) {
                chat.startClient(argv[3]);
            } else {
                chat.startClient(DEFAULT_IP);
            }
        } else {
            std::cout << "Invalid arguments\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
