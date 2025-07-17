#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <fstream>      // for file I/O
#include <ctime>        // for time()
#include <iomanip>      // for formatting timestamp
#include <sstream>      // for stringstream
#include <string>

#pragma comment(lib, "ws2_32.lib")

#define MAX_CLIENTS 100

#include <map>   // for name counting
#include <algorithm>

#include <set>

std::set<std::string> promotedAdmins;

std::set<std::string> mutedUsers;
const std::string MUTED_FILE = "muted.txt";

std::set<std::string> bannedUsers;
std::map<std::string, int> nameCount;
std::string usernames[MAX_CLIENTS];

bool isAdmin[MAX_CLIENTS] = { false };

std::set<std::string> lockedGroups;

SOCKET clients[MAX_CLIENTS];
int clientCount = 0;
CRITICAL_SECTION cs; // Windows mutex

std::string userDomains[MAX_CLIENTS];

struct ClientInfo {
    SOCKET socket;
    int index;
};

std::string motd;  // existing variable, ensure it's here

const std::string MOTD_FILE = "motd.txt";

const std::string ADMIN_PASSWORD = "secure123";  // Change as needed

bool isAuthenticated[MAX_CLIENTS] = {false};

std::string getCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* local = std::localtime(&now);
    std::ostringstream oss;
    oss << "[" << std::put_time(local, "%Y-%m-%d %H:%M:%S") << "]";
    return oss.str();
}

int totalMessagesSent = 0;
int totalWarningsIssued = 0;

void saveAdmins() {
    std::ofstream out("admins.txt");
    for (const auto& adminName : promotedAdmins) {
        out << adminName << "\n";
    }
    out.close();
}

void loadMOTD() {
    std::ifstream file(MOTD_FILE);
    if (file.is_open()) {
        std::getline(file, motd);
        file.close();
    }
}

void saveMOTD() {
    std::ofstream file(MOTD_FILE);
    if (file.is_open()) {
        file << motd << std::endl;
        file.close();
    }
}

void archiveChatLog() {
    time_t now = time(0);
    tm* localTime = localtime(&now);

    char filename[64];
    strftime(filename, sizeof(filename), "chatlog_%Y%m%d.txt", localTime);

    std::ifstream src("chatlog.txt", std::ios::binary);
    std::ofstream dst(filename, std::ios::binary);

    dst << src.rdbuf();

    src.close();
    dst.close();
}

void loadAdmins() {
    std::ifstream in("admins.txt");
    std::string line;
    while (std::getline(in, line)) {
        promotedAdmins.insert(line);
    }
    in.close();
}

// Check if a user exists in the connected clients list
bool userExists(const std::string& targetUser) {
    EnterCriticalSection(&cs); // thread-safe
    for (int i = 0; i < clientCount; ++i) {
        if (usernames[i] == targetUser) {
            LeaveCriticalSection(&cs);
            return true;
        }
    }
    LeaveCriticalSection(&cs);
    return false;
}

void logUserActivity(const std::string& event) {
    std::ofstream log("user_activity.log", std::ios::app);
    if (log.is_open()) {
        log << getCurrentTimestamp() << " " << event << std::endl;
        log.close();
    }
}

void loadMutedUsers() {
    mutedUsers.clear();
    std::ifstream file(MUTED_FILE);
    std::string name;
    while (getline(file, name)) {
        mutedUsers.insert(name);
    }
    file.close();
}

void saveMutedUsers() {
    std::ofstream file(MUTED_FILE);
    for (const auto& name : mutedUsers) {
        file << name << std::endl;
    }
    file.close();
}

void loadBannedUsers() {
    std::ifstream in("banned.txt");
    std::string name;
    while (in >> name) bannedUsers.insert(name);
}

void saveBannedUser(const std::string& name) {
    std::ofstream out("banned.txt", std::ios::app);
    out << name << "\n";
}

void logMessageToFile(const std::string& message) {
    std::ofstream logFile("chatlog.txt", std::ios::app); // append mode
    if (logFile.is_open()) {
        logFile << getCurrentTimestamp() << " " << message << std::endl;
        logFile.close();
    }
}

std::string xorEncryptDecrypt(const std::string& input) {
    std::string output = input;
    char key = 'K'; // simple XOR key

    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key;
    }

    return output;
}

void broadcastGlobal(const std::string& msg, SOCKET sender, bool includeSender = true) {
    EnterCriticalSection(&cs);
    for (int i = 0; i < clientCount; ++i) {
        if (includeSender || clients[i] != sender) {
            send(clients[i], msg.data(), static_cast<int>(msg.size()), 0);
        }
    }
    LeaveCriticalSection(&cs);
}

void broadcast(const std::string& msg, SOCKET sender, const std::string& senderDomain, bool includeSender = true) {
    EnterCriticalSection(&cs);
    for (int i = 0; i < clientCount; ++i) {
        if (userDomains[i] == senderDomain) {  // Same domain only
            if (includeSender || clients[i] != sender) {
                send(clients[i], msg.data(), static_cast<int>(msg.size()), 0);
            }
        }
    }
    LeaveCriticalSection(&cs);
}

DWORD WINAPI handleClient(LPVOID socketPtr) {
    ClientInfo* info = (ClientInfo*)socketPtr;
    SOCKET clientSocket = info->socket;
    int clientIndex = info->index;
    delete info;

    char buffer[2048] = {0};
    int bytesReceived;

    // Receive username from client
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        closesocket(clientSocket);
        return 0;
    }

    std::string combined(buffer, bytesReceived);

    // Try to split into encryptedUsername and leftoverMessage using newline
    size_t newlinePos = combined.find('\n');
    std::string encryptedUsername = (newlinePos != std::string::npos) ? combined.substr(0, newlinePos) : combined;
    std::string leftover = (newlinePos != std::string::npos) ? combined.substr(newlinePos + 1) : "";

    std::string baseName = xorEncryptDecrypt(encryptedUsername);

    if (bannedUsers.count(baseName)) {
    std::string bannedMsg = xorEncryptDecrypt("⛔ You are banned from this server.\n");
    send(clientSocket, bannedMsg.c_str(), bannedMsg.length(), 0);
    closesocket(clientSocket);
    return 0;
    }

    // Assign unique username (e.g., kartik1, kartik2)
    std::string finalName;
    EnterCriticalSection(&cs);
    int count = ++nameCount[baseName]; // increment usage count
    finalName = (count == 1) ? baseName : baseName + std::to_string(count);
    usernames[clientIndex] = finalName; // store the final assigned name
    LeaveCriticalSection(&cs);

    std::cout << "🧍 Assigned username: " << finalName << std::endl;

    if (finalName == "admin") {
        isAdmin[clientIndex] = true;
    }
    // Check if promoted before
    if (promotedAdmins.find(finalName) != promotedAdmins.end() || finalName == "admin") {
        isAdmin[clientIndex] = true;
    }

    // Receive domain/group name
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived <= 0) {
        closesocket(clientSocket);
        return 0;
    }
    std::string encryptedDomain(buffer, bytesReceived);
    std::string domainName = xorEncryptDecrypt(encryptedDomain);
    userDomains[clientIndex] = domainName;   // Store domain name for the client

    std::cout << "🏷️ " << finalName << " joined domain/group: " << domainName << std::endl;

    logUserActivity(finalName + " joined domain: " + domainName);

    if (lockedGroups.find(domainName) != lockedGroups.end() && usernames[clientIndex] != "admin") {
        std::string lockedMsg = xorEncryptDecrypt("🔒 This group is currently locked. You cannot join.");
        send(clientSocket, lockedMsg.c_str(), lockedMsg.length(), 0);
        closesocket(clientSocket);
        return 0;
    }

    if (!motd.empty()) {
        std::string motdMessage = xorEncryptDecrypt("📢 Message of the Day: " + motd + "\n");
        send(clientSocket, motdMessage.c_str(), motdMessage.length(), 0);
    }

    // ✅ Immediately process leftover as first message if it exists
    if (!leftover.empty()) {
        std::string decryptedFirstMsg = xorEncryptDecrypt(leftover);
        decryptedFirstMsg.erase(std::remove(decryptedFirstMsg.begin(), decryptedFirstMsg.end(), '\r'), decryptedFirstMsg.end());
        decryptedFirstMsg.erase(std::remove(decryptedFirstMsg.begin(), decryptedFirstMsg.end(), '\n'), decryptedFirstMsg.end());

        if (!decryptedFirstMsg.empty()) {
            std::string finalMessage = finalName + ": " + decryptedFirstMsg;
            std::string encryptedMessage = xorEncryptDecrypt(finalMessage);
            broadcast(encryptedMessage, clientSocket, userDomains[clientIndex], true);
            logMessageToFile(finalMessage);
        }
    }

    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        std::string decrypted = xorEncryptDecrypt(std::string(buffer, bytesReceived));
        decrypted.erase(std::remove(decrypted.begin(), decrypted.end(), '\r'), decrypted.end());
        decrypted.erase(std::remove(decrypted.begin(), decrypted.end(), '\n'), decrypted.end());

        if (decrypted == "/exit") {
            std::string exitMsg = usernames[clientIndex] + " has left the chat.";
            std::string encryptedExitMsg = xorEncryptDecrypt(exitMsg);

            broadcast(encryptedExitMsg, clientSocket, userDomains[clientIndex], false);
            logMessageToFile(exitMsg);
            
            break;  // breaks the recv() loop and triggers cleanup
        }
        
        if (!decrypted.empty()) {
        // Trim whitespace/control chars
        decrypted.erase(std::remove_if(decrypted.begin(), decrypted.end(),
        [](char c) { return c == '\r' || c == '\n' || c == '\0'; }), decrypted.end());
            if (decrypted.rfind("/auth ", 0) == 0) {
                std::string attemptedPassword = decrypted.substr(6);

                if (attemptedPassword == ADMIN_PASSWORD) {
                    isAuthenticated[clientIndex] = true;
                    std::string success = xorEncryptDecrypt("✅ Authentication successful. You can now use admin commands.");
                    send(clientSocket, success.c_str(), success.length(), 0);
                } else {
                    std::string failure = xorEncryptDecrypt("❌ Wrong password. Authentication failed.");
                    send(clientSocket, failure.c_str(), failure.length(), 0);
                }
            }
            if (decrypted == "/list") {
                // existing /list logic
                std::string userList = "🧍 Online users: ";
                EnterCriticalSection(&cs);            
                for (int i = 0; i < clientCount; ++i) {
                    userList += usernames[i];
                    if (isAdmin[i]) userList += " (admin)";
                    if (i != clientCount - 1) userList += ", ";
                }
                LeaveCriticalSection(&cs);
                std::string encryptedUserList = xorEncryptDecrypt(userList);
                send(clientSocket, encryptedUserList.c_str(), encryptedUserList.size(), 0);
            }

            else if (decrypted.substr(0, 9) == "/whisper ") {
                size_t firstSpace = decrypted.find(' ');
                size_t secondSpace = decrypted.find(' ', firstSpace + 1);
                if (secondSpace != std::string::npos) {
                    std::string targetUser = decrypted.substr(firstSpace + 1, secondSpace - firstSpace - 1);
                    std::string privateMsg = decrypted.substr(secondSpace + 1);

                    SOCKET targetSocket = INVALID_SOCKET;
                    EnterCriticalSection(&cs);
                    for (int i = 0; i < clientCount; ++i) {
                        // Convert both to lowercase for comparison
                        std::string stored = usernames[i];
                        std::string target = targetUser;
                        std::transform(stored.begin(), stored.end(), stored.begin(), ::tolower);
                        std::transform(target.begin(), target.end(), target.begin(), ::tolower);
                        if (stored == target)
                        {
                            targetSocket = clients[i];
                            break;
                        }
                    }
                    LeaveCriticalSection(&cs);

                    if (targetSocket != INVALID_SOCKET) {
                        std::string whisperText = "[whisper from " + usernames[clientIndex] + "]: " + privateMsg;
                        std::string encryptedWhisper = xorEncryptDecrypt(whisperText);
                        send(targetSocket, encryptedWhisper.c_str(), encryptedWhisper.length(), 0);
                    } else {
                        std::string errorMsg = "❌ User '" + targetUser + "' not found.";
                        std::string encryptedError = xorEncryptDecrypt(errorMsg);
                        send(clientSocket, encryptedError.c_str(), encryptedError.length(), 0);
                    }
                } else {
                    std::string errorMsg = "⚠️ Usage: /whisper <username> <message>";
                    std::string encryptedError = xorEncryptDecrypt(errorMsg);
                    send(clientSocket, encryptedError.c_str(), encryptedError.length(), 0);
                }
            }
            else if (decrypted.substr(0, 5) == "/ban ") {
                if (!isAdmin[clientIndex]) {
                    std::string notAllowed = xorEncryptDecrypt("⛔ Only admin can ban users.");
                    send(clientSocket, notAllowed.c_str(), notAllowed.size(), 0);
                    continue;
                }
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }
                std::string toBan = decrypted.substr(5);
                if (userExists(toBan)) {
                    EnterCriticalSection(&cs);
                    auto it = std::find(usernames, usernames + clientCount, toBan);
                    if (it != usernames + clientCount) {
                        int banIndex = it - usernames;
                        std::string baseToBan = toBan;
                        size_t digitStart = baseToBan.find_first_of("0123456789");
                        if (digitStart != std::string::npos) baseToBan = baseToBan.substr(0, digitStart);

                        bannedUsers.insert(baseToBan);
                        saveBannedUser(baseToBan);

                        std::string banMsg = xorEncryptDecrypt("⛔ " + toBan + " has been banned by admin.");
                        broadcast(banMsg, clientSocket, userDomains[clientIndex], true);
                        closesocket(clients[banIndex]);
                        clients[banIndex] = clients[clientCount - 1];
                        usernames[banIndex] = usernames[clientCount - 1];
                        clientCount--;
                    } else {
                        std::string notFound = xorEncryptDecrypt("🚫 User not found: " + toBan);
                        send(clientSocket, notFound.c_str(), notFound.length(), 0);
                    }
                    LeaveCriticalSection(&cs);
                } else {
                    std::string notFoundMsg = "❌ User not found: " + toBan;
                    std::string encrypted = xorEncryptDecrypt(notFoundMsg);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                }
            }
            else if (decrypted == "/help") {
                std::string helpMsg =
                    "🛠️ Available Commands:\n"
                    "/list                         - Show online users\n"
                    "/listgroups                   - Show all active groups\n"
                    "/auth                         - Authenticate with password\n"
                    "/whisper <user> <msg>         - Send private message\n"
                    "/rename <newname>             - Change your username\n"
                    "/changegroup <group>          - Change your group/domain\n"
                    "/admins                       - View current admins\n"
                    "/motd                         - Display the message of the day\n"
                    "/kick <user>                  - [admin] Kick user from server\n"
                    "/broadcast <msg>              - [admin] Send global broadcast\n"
                    "/ban <username>               - [admin] Ban user by base name\n"
                    "/mute <username>              - [admin] Mute user\n"
                    "/unmute <username>            - [admin] Unmute user\n"
                    "/clearlog                     - [admin] Clear chat log\n"
                    "/kickgroup <group>            - [admin] Kick all users from a group (without deleting group)\n"
                    "/lockgroup <group>            - [admin] Lock a group\n"
                    "/unlockgroup <group>          - [admin] Unlock a group\n"
                    "/showlog                      - [admin] Display chat logs\n"
                    "/savegroups                   - [admin] Save active group list\n"
                    "/whois <username>             - [admin] Show group & status of user\n"
                    "/deletegroup <group>          - [admin] Kick all users and remove the group\n"
                    "/promote <user>               - [admin] Grant admin rights to online user\n"
                    "/demote <user>                - [admin] Remove admin rights from online user\n"
                    "/warn <user> <reason>         - [admin] Warn user\n"
                    "/setmotd <motd>               - [admin] Set the message of the day\n"
                    "/archive                      - [admin] Archive chat logs\n"
                    "/stats                        - [admin] Display server statistics\n"
                    "/exit                         - Disconnect from chat\n"
                    "/help                         - Show this help menu\n";
                
                std::istringstream stream(helpMsg);
                std::string line;
                while (std::getline(stream, line)) {
                    std::string encryptedLine = xorEncryptDecrypt(line + "\n");
                    send(clientSocket, encryptedLine.c_str(), encryptedLine.length(), 0);
                    Sleep(50); // small delay to prevent flooding
                }
            }
            else if (decrypted.substr(0, 7) == "/whois ") {
                if (!isAdmin[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ Only admin can use /whois.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetUser = decrypted.substr(7);

                bool found = false;
                std::string userGroup;
                EnterCriticalSection(&cs);
                for (int i = 0; i < clientCount; ++i) {
                    if (usernames[i] == targetUser) {
                        userGroup = userDomains[i];
                        found = true;
                        break;
                    }
                }
                LeaveCriticalSection(&cs);

                std::string result;
                if (found) {
                    result = "ℹ️ User '" + targetUser + "' is currently in group '" + userGroup + "'. Status: Online.";
                } else {
                    result = "❌ User '" + targetUser + "' is not connected.";
                }

                std::string encryptedResult = xorEncryptDecrypt(result);
                send(clientSocket, encryptedResult.c_str(), encryptedResult.length(), 0);
            }

            else if (decrypted.rfind("/rename ", 0) == 0) {
                std::string newName = decrypted.substr(8);

                if (newName.empty()) return 0;

                if (newName == "admin") {
                    std::string denied = xorEncryptDecrypt("❌ You cannot rename yourself to 'admin'.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                EnterCriticalSection(&cs);
                int count = ++nameCount[newName];
                std::string finalNewName = (count == 1) ? newName : newName + std::to_string(count);
                std::string oldName = usernames[clientIndex];
                usernames[clientIndex] = finalNewName;
                LeaveCriticalSection(&cs);

                std::string notice = "🔄 " + oldName + " changed name to " + finalNewName;
                std::string encryptedNotice = xorEncryptDecrypt(notice);
                broadcast(encryptedNotice, clientSocket, userDomains[clientIndex], true);
                logMessageToFile(notice);
            }
            else if (decrypted == "/clearlog") {
                if (isAdmin[clientIndex]) {
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }
                    std::ofstream ofs("chatlog.txt", std::ios::trunc); // truncate log
                    ofs.close();
                    std::string confirmation = "🧹 Chat log has been cleared by admin.";
                    std::string encryptedConfirmation = xorEncryptDecrypt(confirmation);
                    broadcast(encryptedConfirmation, clientSocket, userDomains[clientIndex], true);
                    logMessageToFile("🧹 Chat log cleared by admin.");
                } else {
                    std::string error = "❌ Only 'admin' can clear the chat log.";
                    std::string encryptedError = xorEncryptDecrypt(error);
                    send(clientSocket, encryptedError.c_str(), encryptedError.length(), 0);
                }
            }
            if (decrypted.rfind("/mute ", 0) == 0 && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }
                std::string targetUser = decrypted.substr(6);
                if (userExists(targetUser)) {
                    EnterCriticalSection(&cs);
                    mutedUsers.insert(targetUser);
                    saveMutedUsers();
                    LeaveCriticalSection(&cs);

                    std::string msg = "🔇 Muted " + targetUser + ".";
                    std::string encrypted = xorEncryptDecrypt(msg);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                } else {
                    std::string msg = "❌ User not found: " + targetUser;
                    std::string encrypted = xorEncryptDecrypt(msg);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                }
            }
            else if (decrypted.rfind("/unmute ", 0) == 0 && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetUser = decrypted.substr(8);
                if (userExists(targetUser)) {
                    EnterCriticalSection(&cs);
                    mutedUsers.erase(targetUser);
                    saveMutedUsers();
                    LeaveCriticalSection(&cs);

                    std::string confirmation = "🔊 Unmuted " + targetUser + ".";
                    std::string encrypted = xorEncryptDecrypt(confirmation);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                } else {
                    std::string msg = "❌ User not found: " + targetUser;
                    std::string encrypted = xorEncryptDecrypt(msg);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                }
            }
            else if (decrypted.substr(0, 6) == "/kick ") {
                std::string targetUser = decrypted.substr(6);
                if (userExists(targetUser)) {
                    EnterCriticalSection(&cs);
                    bool isAdminNow = isAdmin[clientIndex];
                    int targetIndex = -1;

                    // Find the index of the user to be kicked
                    for (int i = 0; i < clientCount; ++i) {
                        if (usernames[i] == targetUser) {
                            targetIndex = i;
                            break;
                        }
                    }

                    if (!isAdmin[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ Only admin can kick users.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }
                     else if (targetIndex == -1) {
                        std::string notFound = xorEncryptDecrypt("❗ User not found: " + targetUser);
                        send(clientSocket, notFound.c_str(), notFound.length(), 0);
                    } else {
                        std::string notice = "🛑 " + usernames[targetIndex] + " has been kicked out by admin.";
                        std::string encrypted = xorEncryptDecrypt(notice);
                        broadcast(encrypted, clientSocket, userDomains[clientIndex], true);
                        // Disconnect the client
                        SOCKET kickedSocket = clients[targetIndex];
                        closesocket(kickedSocket);

                        // Remove from arrays
                        clients[targetIndex] = clients[clientCount - 1];
                        usernames[targetIndex] = usernames[clientCount - 1];
                        --clientCount;
                    }

                    LeaveCriticalSection(&cs);
                } else {
                    std::string msg = "❌ User not found: " + targetUser;
                    std::string encrypted = xorEncryptDecrypt(msg);
                    send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
                }          
            }
            else if (decrypted == "/listgroups") {
                std::set<std::string> uniqueGroups;
                EnterCriticalSection(&cs);
                for (int i = 0; i < clientCount; ++i) {
                    uniqueGroups.insert(userDomains[i]);
                }
                LeaveCriticalSection(&cs);

                std::string groupList = "📁 Active Groups: ";
                for (const auto& group : uniqueGroups) {
                    groupList += group + ", ";
                }
                if (!uniqueGroups.empty())
                    groupList.pop_back(), groupList.pop_back(); // Remove last comma and space

                std::string encryptedList = xorEncryptDecrypt(groupList);
                send(clientSocket, encryptedList.c_str(), encryptedList.length(), 0);
            }
            else if (decrypted.rfind("/changegroup ", 0) == 0) {
                std::string newGroup = decrypted.substr(13);

                EnterCriticalSection(&cs);
                userDomains[clientIndex] = newGroup;
                LeaveCriticalSection(&cs);

                std::string msg = "🔄 You moved to group/domain: " + newGroup;
                std::string encryptedMsg = xorEncryptDecrypt(msg);
                send(clientSocket, encryptedMsg.c_str(), encryptedMsg.length(), 0);

                std::string notice = usernames[clientIndex] + " joined this group.";
                std::string encryptedNotice = xorEncryptDecrypt(notice);
                broadcast(encryptedNotice, clientSocket, newGroup, true);
            }
            else if (decrypted.rfind("/kickgroup ", 0) == 0) {
                if (!isAdmin[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ Only admin can use /kickgroup.");
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetGroup = decrypted.substr(11);
                if (targetGroup.empty()) {
                    std::string error = xorEncryptDecrypt("⚠️ Usage: /kickgroup <groupname>");
                    send(clientSocket, error.c_str(), error.length(), 0);
                    continue;
                }

                int kickedCount = 0;

                EnterCriticalSection(&cs);

                for (int i = 0; i < clientCount;) {
                    if (userDomains[i] == targetGroup) {
                        std::string notice = "⛔ Disconnected by admin from group '" + targetGroup + "'.";
                        std::string encryptedNotice = xorEncryptDecrypt(notice);
                        send(clients[i], encryptedNotice.c_str(), encryptedNotice.length(), 0);

                        closesocket(clients[i]);

                        // Remove user from arrays
                        clients[i] = clients[clientCount - 1];
                        usernames[i] = usernames[clientCount - 1];
                        userDomains[i] = userDomains[clientCount - 1];
                        --clientCount;

                        ++kickedCount;
                        // Note: don't increment i, as current index now holds swapped last client
                    } else {
                        ++i; // move to next client
                    }
                }

                LeaveCriticalSection(&cs);

                std::string resultMsg = "🛑 Admin kicked " + std::to_string(kickedCount) +
                                        " users from group '" + targetGroup + "'.";
                std::string encryptedResult = xorEncryptDecrypt(resultMsg);
                send(clientSocket, encryptedResult.c_str(), encryptedResult.length(), 0);
            }
            else if (decrypted.substr(0, 10) == "/lockgroup" && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string groupToLock = decrypted.substr(11);
                lockedGroups.insert(groupToLock);

                std::string msg = "🔒 Group '" + groupToLock + "' has been locked.";
                std::string encrypted = xorEncryptDecrypt(msg);
                broadcast(encrypted, clientSocket, userDomains[clientIndex], true);
            }
            else if (decrypted.substr(0, 12) == "/unlockgroup" && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string groupToUnlock = decrypted.substr(13);
                lockedGroups.erase(groupToUnlock);

                std::string msg = "🔓 Group '" + groupToUnlock + "' has been unlocked.";
                std::string encrypted = xorEncryptDecrypt(msg);
                broadcast(encrypted, clientSocket, userDomains[clientIndex], true);
            }
            else if (decrypted == "/showlog" && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::ifstream logFile("chatlog.txt");
                if (!logFile.is_open()) {
                    std::string errMsg = xorEncryptDecrypt("⚠️ Could not open chat log.");
                    send(clientSocket, errMsg.c_str(), errMsg.length(), 0);
                } else {
                    std::string line;
                    while (std::getline(logFile, line)) {
                        std::string encryptedLine = xorEncryptDecrypt("📜 " + line);
                        send(clientSocket, encryptedLine.c_str(), encryptedLine.length(), 0);
                        Sleep(50);  // slight delay to avoid flooding
                    }
                    logFile.close();
                }
            }
            else if (decrypted == "/savegroups" && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::ofstream outFile("groups.txt");
                EnterCriticalSection(&cs);

                std::map<std::string, int> groupCounts;
                for (int i = 0; i < clientCount; ++i) {
                    groupCounts[userDomains[i]]++;
                }

                for (const auto& entry : groupCounts) {
                    outFile << entry.first << ": " << entry.second << " members\n";
                }
                LeaveCriticalSection(&cs);

                outFile.close();

                std::string msg = xorEncryptDecrypt("📁 Active groups saved to 'groups.txt'.");
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
            else if (decrypted.substr(0, 13) == "/deletegroup ") {
                if (!isAdmin[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ Only admin can delete groups.");
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }

                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetGroup = decrypted.substr(13);

                int kickedCount = 0;
                EnterCriticalSection(&cs);

                for (int i = 0; i < clientCount; ++i) {
                    if (userDomains[i] == targetGroup) {
                        std::string notice = "⚠️ Group '" + targetGroup + "' is being deleted. You are disconnected.";
                        std::string encryptedNotice = xorEncryptDecrypt(notice);
                        send(clients[i], encryptedNotice.c_str(), encryptedNotice.length(), 0);

                        closesocket(clients[i]);

                        clients[i] = clients[clientCount - 1];
                        usernames[i] = usernames[clientCount - 1];
                        userDomains[i] = userDomains[clientCount - 1];
                        clientCount--;
                        i--;  // recheck swapped index

                        kickedCount++;
                    }
                }

                LeaveCriticalSection(&cs);

                std::string adminMsg = "🗑️ Group '" + targetGroup + "' deleted. " + std::to_string(kickedCount) + " users removed.";
                std::string encryptedAdminMsg = xorEncryptDecrypt(adminMsg);
                send(clientSocket, encryptedAdminMsg.c_str(), encryptedAdminMsg.length(), 0);
            }
            else if (decrypted.rfind("/promote ", 0) == 0) {
                if (!isAdmin[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ Only admins can promote users.");
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }

                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetUser = decrypted.substr(9);
                bool found = false;

                EnterCriticalSection(&cs);
                for (int i = 0; i < clientCount; ++i) {
                    if (usernames[i] == targetUser) {
                        isAdmin[i] = true;
                        promotedAdmins.insert(targetUser);
                        saveAdmins();
                        found = true;
                        break;
                    }
                }
                LeaveCriticalSection(&cs);

                std::string msg = found ? "🆙 " + targetUser + " has been promoted to admin."
                                        : "❌ User not found: " + targetUser;
                std::string encrypted = xorEncryptDecrypt(msg);
                send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
            }
            else if (decrypted.rfind("/demote ", 0) == 0) {
                if (!isAdmin[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ Only admins can demote users.");
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }

                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string targetUser = decrypted.substr(8);
                bool found = false;

                EnterCriticalSection(&cs);
                for (int i = 0; i < clientCount; ++i) {
                    if (usernames[i] == targetUser) {
                        if (usernames[i] == "admin") {
                            found = false;  // Cannot demote default admin
                            break;
                        }
                        isAdmin[i] = false;
                        promotedAdmins.erase(targetUser);
                        saveAdmins();
                        found = true;
                        break;
                    }
                }
                LeaveCriticalSection(&cs);

                std::string msg = found ? "🔻 " + targetUser + " has been demoted from admin."
                                        : "❌ User not found or cannot demote 'admin'.";
                std::string encrypted = xorEncryptDecrypt(msg);
                send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
            }
            else if (decrypted == "/admins") {
                std::string adminList = "👑 Current Admins: ";

                EnterCriticalSection(&cs);
                bool hasAny = false;
                for (int i = 0; i < clientCount; ++i) {
                    if (isAdmin[i]) {
                        adminList += usernames[i] + ", ";
                        hasAny = true;
                    }
                }
                LeaveCriticalSection(&cs);

                if (hasAny)
                    adminList.pop_back(), adminList.pop_back(); // Remove trailing comma

                std::string encryptedList = xorEncryptDecrypt(adminList);
                send(clientSocket, encryptedList.c_str(), encryptedList.length(), 0);
            }
            else if (decrypted.rfind("/broadcast ", 0) == 0 && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                std::string broadcastMsg = decrypted.substr(11);  // skip "/broadcast "
                std::string formattedMsg = "📢 [ADMIN BROADCAST]: " + broadcastMsg;
                std::string encryptedMsg = xorEncryptDecrypt(formattedMsg);
                broadcastGlobal(encryptedMsg, clientSocket, true);
            }
            else if (decrypted.rfind("/setmotd ", 0) == 0 && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                motd = decrypted.substr(9);  // extract new MOTD text
                saveMOTD();                  // save it immediately

                std::string msg = xorEncryptDecrypt("✅ MOTD set: " + motd);
                send(clientSocket, msg.c_str(), msg.length(), 0);
            }
            else if (decrypted == "/motd") {
                std::string message = motd.empty() ? "ℹ️ No MOTD set." : ("📢 Message of the Day: " + motd);
                std::string encrypted = xorEncryptDecrypt(message);
                send(clientSocket, encrypted.c_str(), encrypted.length(), 0);
            }
            if (decrypted.rfind("/warn ", 0) == 0 && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                size_t firstSpace = decrypted.find(' ');
                size_t secondSpace = decrypted.find(' ', firstSpace + 1);

                if (secondSpace != std::string::npos) {
                    std::string targetUser = decrypted.substr(firstSpace + 1, secondSpace - firstSpace - 1);
                    std::string reason = decrypted.substr(secondSpace + 1);

                    SOCKET targetSocket = INVALID_SOCKET;
                    EnterCriticalSection(&cs);
                    for (int i = 0; i < clientCount; ++i) {
                        if (usernames[i] == targetUser) {
                            targetSocket = clients[i];
                            break;
                        }
                    }
                    LeaveCriticalSection(&cs);

                    if (targetSocket != INVALID_SOCKET) {
                        std::string warningMsg = "⚠️ [Admin Warning] " + reason;
                        std::string encryptedWarning = xorEncryptDecrypt(warningMsg);
                        send(targetSocket, encryptedWarning.c_str(), encryptedWarning.length(), 0);

                        std::string logEntry = "⚠️ Admin warned " + targetUser + ": " + reason;
                        logMessageToFile(logEntry);
                    } else {
                        std::string notFound = xorEncryptDecrypt("❌ User not found: " + targetUser);
                        send(clientSocket, notFound.c_str(), notFound.length(), 0);
                    }
                } else {
                    std::string error = xorEncryptDecrypt("⚠️ Usage: /warn <username> <reason>");
                    send(clientSocket, error.c_str(), error.length(), 0);
                }
            }
            else if (decrypted == "/stats" && isAdmin[clientIndex]) {
                if (!isAuthenticated[clientIndex]) {
                    std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                    send(clientSocket, denied.c_str(), denied.length(), 0);
                    continue;
                }

                int totalClients, totalGroups, totalBanned, totalMuted;

                EnterCriticalSection(&cs);
                totalClients = clientCount;
                totalGroups = std::set<std::string>(userDomains, userDomains + clientCount).size();
                totalBanned = bannedUsers.size();
                totalMuted = mutedUsers.size();
                LeaveCriticalSection(&cs);

                std::string statsMsg = "📊 Server Stats:\n";
                statsMsg += "• Total Connected Clients: " + std::to_string(totalClients) + "\n";
                statsMsg += "• Total Active Groups: " + std::to_string(totalGroups) + "\n";
                statsMsg += "• Total Banned Users: " + std::to_string(totalBanned) + "\n";
                statsMsg += "• Total Muted Users: " + std::to_string(totalMuted);

                std::string encryptedStats = xorEncryptDecrypt(statsMsg);
                send(clientSocket, encryptedStats.c_str(), encryptedStats.length(), 0);
            }
            if (decrypted == "/archive") {
                if (isAdmin[clientIndex]) {
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }

                    archiveChatLog();

                    std::string msg = "📦 Chat log archived successfully.";
                    std::string encryptedMsg = xorEncryptDecrypt(msg);
                    send(clientSocket, encryptedMsg.c_str(), encryptedMsg.length(), 0);
                } else {
                    std::string error = xorEncryptDecrypt("❌ Only admin can archive chat log.");
                    if (!isAuthenticated[clientIndex]) {
                        std::string denied = xorEncryptDecrypt("❌ You must authenticate using /auth <password> to use admin commands.");
                        send(clientSocket, denied.c_str(), denied.length(), 0);
                        continue;
                    }

                    send(clientSocket, error.c_str(), error.length(), 0);
                }
            }
            if (mutedUsers.find(usernames[clientIndex]) != mutedUsers.end()) {
                std::string mutedNotice = xorEncryptDecrypt("🔇 You are muted. Messages won’t be sent.");
                send(clientSocket, mutedNotice.c_str(), mutedNotice.length(), 0);
                continue; // Suppress broadcast
            }
            else {
                std::string finalMessage = usernames[clientIndex] + ": " + decrypted;
                std::string encryptedMessage = xorEncryptDecrypt(finalMessage);
                broadcast(encryptedMessage, clientSocket, userDomains[clientIndex], true);
                logMessageToFile(finalMessage);
            }
        }
    }

    // Remove client on disconnect
    EnterCriticalSection(&cs);
    for (int i = 0; i < clientCount; ++i) {
        if (clients[i] == clientSocket) {
            clients[i] = clients[clientCount - 1];
            usernames[i] = usernames[clientCount - 1];
            --clientCount;
            break;
        }
    }
    LeaveCriticalSection(&cs);

    logUserActivity(usernames[clientIndex] + " left domain: " + userDomains[clientIndex]);

    closesocket(clientSocket);
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket;
    sockaddr_in serverAddr, clientAddr;
    int clientSize = sizeof(clientAddr);

    InitializeCriticalSection(&cs);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
        std::cerr << "Winsock init failed\n";
        return 1;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, SOMAXCONN);

    std::cout << "📡 Server listening on port 8080...\n";

    archiveChatLog();
    loadMOTD();

    while (true) {
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "❌ Accept failed\n";
            continue;
        }

        std::cout << "[+] Client connected\n";

        int assignedIndex = -1;

        EnterCriticalSection(&cs);
        if (clientCount < MAX_CLIENTS) {
            assignedIndex = clientCount;
            clients[assignedIndex] = clientSocket;
            clientCount++;
        }
        LeaveCriticalSection(&cs);

        ClientInfo* info = new ClientInfo{ clientSocket, assignedIndex };
        CreateThread(NULL, 0, handleClient, info, 0, NULL);

    }

    closesocket(serverSocket);
    DeleteCriticalSection(&cs);
    WSACleanup();
    return 0;
}
