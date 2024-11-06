#include <iostream>
#include <string>
#include <random>
#include <array>
#include <chrono>
#include <thread>
#include <fstream>
#include <cstring>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include <iomanip>

const std::string RESET = "\033[0m";
const std::string GREEN = "\033[32m";
const std::string BLUE = "\033[34m";
const std::string YELLOW = "\033[33m";
const std::string RED = "\033[31m";

const std::vector<std::string> BRAILLE_FRAMES = {
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
};

class ConnectionCode {
private:
    static const std::vector<std::string> word_list;
    
public:
    static std::string generate() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> num_dist(0, 9999);
        std::uniform_int_distribution<> word_dist(0, word_list.size() - 1);
        
        std::string code = std::to_string(num_dist(gen));
        code = std::string(4 - code.length(), '0') + code;
        
        for (int i = 0; i < 3; i++) {
            code += "-" + word_list[word_dist(gen)];
        }
        
        return code;
    }
};

const std::vector<std::string> ConnectionCode::word_list = {
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "golf", "hotel", "india", "juliet", "kilo", "lima"
    // Add more words as needed
};

class FileTransfer {
private:
    std::string filename;
    size_t filesize;
    std::string hash;
    size_t bytes_transferred;
    std::chrono::steady_clock::time_point start_time;
    int socket_fd;
    
    std::string calculate_sha256(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        char buffer[4096];
        while (file.read(buffer, sizeof(buffer))) {
            SHA256_Update(&sha256, buffer, file.gcount());
        }
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &sha256);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
    
public:
    FileTransfer(const std::string& fname) : filename(fname) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        filesize = file.tellg();
        file.close();
        hash = calculate_sha256(filename);
        bytes_transferred = 0;
        start_time = std::chrono::steady_clock::now();
    }
    
    void display_stats() {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        double speed = bytes_transferred / (duration ? duration : 1) / 1024.0; // KB/s
        double progress = (double)bytes_transferred / filesize * 100;
        
        std::cout << "\r" << BLUE;
        std::cout << BRAILLE_FRAMES[(duration % BRAILLE_FRAMES.size())] << " ";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Progress: " << progress << "% ";
        std::cout << "Speed: " << speed << " KB/s ";
        std::cout << "Time: " << duration << "s" << RESET;
        std::cout.flush();
    }
    
    // Other transfer-related methods would go here
};

class P2PApplication {
private:
    bool is_sender;
    std::string connection_code;
    FileTransfer* transfer;
    
    void setup_sender() {
        connection_code = ConnectionCode::generate();
        std::cout << GREEN << "Your connection code: " << connection_code << RESET << std::endl;
        // Setup socket and wait for connection
    }
    
    void setup_receiver() {
        std::cout << YELLOW << "Enter connection code: " << RESET;
        std::cin >> connection_code;
        // Setup socket and connect to sender
    }
    
public:
    P2PApplication(bool sender, const std::string& filename) 
        : is_sender(sender), transfer(nullptr) {
        if (filename != "") {
            transfer = new FileTransfer(filename);
        }
    }
    
    void run() {
        if (is_sender) {
            setup_sender();
        } else {
            setup_receiver();
        }
        
        // Main transfer loop would go here
        while (true) {
            transfer->display_stats();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            // Handle transfer logic
        }
    }
    
    ~P2PApplication() {
        delete transfer;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " [send|receive] [filename]" << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string filename = (argc > 2) ? argv[2] : "";
    
    P2PApplication app(mode == "send", filename);
    app.run();
    
    return 0;
}
