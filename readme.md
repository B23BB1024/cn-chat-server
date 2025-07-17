# CN Chat Server (C++)

A multi-client encrypted chat server built using C++ raw sockets (WinAPI) for Windows. This project supports multiple groups (domains), private messaging, full admin control, and persistent logging.

---

## 🚀 Features

- **Group-based chat (domains)**
- **XOR-based message encryption**
- **Private messaging (`/whisper`)**
- **Admin system:**
  - `/promote` and `/demote`
  - `/ban`, `/mute`, `/kick`
  - `/deletegroup` and `/kickgroup`
- **Global broadcasts (`/broadcast`)**
- **MOTD system (`/setmotd` and `/motd`)**
- **Chat archiving (`/archive`)**
- **Server statistics (`/stats`)**
- **Persistent logs (`chatlog.txt`, `user_activity.log`)**

---

## 🛠️ Commands Overview

| Command                | Description                          |
|------------------------|--------------------------------------|
| `/list`                | Show online users                    |
| `/listgroups`          | Show all active groups               |
| `/whisper <user> <msg>`| Private message                      |
| `/rename <newname>`    | Change username                      |
| `/changegroup <group>` | Switch group/domain                  |
| `/broadcast <msg>`     | [admin] Global broadcast             |
| `/ban <user>`          | [admin] Ban user                     |
| `/mute <user>`         | [admin] Mute user                    |
| `/unmute <user>`       | [admin] Unmute user                  |
| `/kick <user>`         | [admin] Kick user                    |
| `/kickgroup <group>`   | [admin] Kick all users in a group    |
| `/deletegroup <group>` | [admin] Kick and delete group        |
| `/lockgroup <group>`   | [admin] Lock group (block join)      |
| `/unlockgroup <group>` | [admin] Unlock group                 |
| `/setmotd <text>`      | [admin] Set Message of the Day       |
| `/motd`                | Show current MOTD                    |
| `/archive`             | Archive current chat log             |
| `/stats`               | Show server statistics               |
| `/showlog`             | View chat log                        |
| `/savegroups`          | Save active groups                   |
| `/whois <user>`        | [admin] User status                  |
| `/promote <user>`      | [admin] Promote user to admin        |
| `/demote <user>`       | [admin] Demote user                  |
| `/help`                | Show all commands                    |
| `/exit`                | Disconnect                           |

---

## 🛠️ Setup & Build Instructions

### 💻 Requirements:
- Windows (Tested on Windows 10/11)
- MinGW or Visual Studio for compilation

### 🏗️ Compilation:
```bash
# Compile Server
g++ server.cpp -o server.exe -lws2_32

# Compile Client
g++ client.cpp -o client.exe -lws2_32
