#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread> // Only used for Sleep, can be removed if you want WinAPI Sleep

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8080
#define BUFFER_SIZE 1024

struct ThreadData {
    SOCKET sock;
    std::string username;
};

std::string xorEncryptDecrypt(const std::string& input) {
    std::string output = input;
    char key = 'K';
    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key;
    }
    return output;
}

void displayWithTimestamp(const std::string& message) {
    // Get current local time
    time_t now = time(0);
    tm* localtm = localtime(&now);

    // Format time as [HH:MM:SS]
    char timeStr[9]; // HH:MM:SS
    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", localtm);

    // Display message with timestamp
    std::cout << "[" << timeStr << "] " << message << std::endl;
}

DWORD WINAPI receiveMessages(LPVOID param) {
    ThreadData* data = (ThreadData*)param;
    SOCKET clientSocket = data->sock;
    std::string myUsername = data->username;
    delete data;

    char buffer[1024];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        std::string encrypted(buffer, bytesReceived);
        std::string decrypted = xorEncryptDecrypt(encrypted);

        if (!decrypted.empty()) {
            if (decrypted.rfind(myUsername + ": ", 0) == 0) {
                // Message starts with your own username—suppress it
                continue;
            }

            displayWithTimestamp(decrypted);
            std::cout.flush();
        }

    }

    std::cout << "\n❌ Server closed connection.\n";
    exit(0);
    return 0;
}


int main() {
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        std::cerr << "❌ WSAStartup failed.\n";
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "❌ Socket creation failed.\n";
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "❌ Connection failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Enter your username: ";
    std::string username;
    std::getline(std::cin, username);

    // Send encrypted username + newline
    std::string encryptedUsername = xorEncryptDecrypt(username) + "\n";
    send(sock, encryptedUsername.c_str(), encryptedUsername.size(), 0);

    // After sending username
    std::cout << "Enter domain/group name: ";
    std::string domainName;
    std::getline(std::cin, domainName);

    // Send encrypted domain name
    std::string encryptedDomain = xorEncryptDecrypt(domainName);
    send(sock, encryptedDomain.c_str(), encryptedDomain.size(), 0);

    std::cout << "🎉 Welcome, " << username << "! Type /help to see available commands.\n\n";

    std::cout << "✅ Connected! Start chatting:\n";

    // Start receiving thread
    ThreadData* data = new ThreadData{sock, username};
    CreateThread(NULL, 0, receiveMessages, data, 0, NULL);

    while (true) {
        std::cout << "> ";
        std::string message;
        std::getline(std::cin, message);
        
        if (message == "/exit") {
        std::string encrypted = xorEncryptDecrypt(message);
        send(sock, encrypted.c_str(), encrypted.length(), 0);
        std::cout << "👋 Disconnected from server.\n";
        break;
        }

        if (!message.empty()) {
            // Display your own sent message immediately with timestamp
            displayWithTimestamp("You: " + message);
            
            // Then send it to the server
            std::string encrypted = xorEncryptDecrypt(message);
            send(sock, encrypted.c_str(), encrypted.length(), 0);
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
