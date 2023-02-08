#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include "json.hpp"
#include <fstream>
#include <sstream>

#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

std::string gamePath;
int targetFPS = 60;

DWORD FindProcessID(const std::string& processName) {
    DWORD pid = 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (entry.szExeFile == processName) {
                pid = entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);

    return pid;
}

std::uint8_t* PatternScan(void* module, const char* signature) {
    static auto pattern_to_byte = [](const char *pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char *>(pattern);
        auto end = const_cast<char *>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?') {
                    ++current;
                }
                bytes.push_back(-1);
            } else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dosHeader = (PIMAGE_DOS_HEADER) module;
    auto ntHeaders = (PIMAGE_NT_HEADERS) ((std::uint8_t *) module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t *>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return &scanBytes[i];
        }
    }

    return nullptr;
}

bool GetModule(DWORD pid, const std::string& ModuleName, PMODULEENTRY32 pEntry) {
    if (!pEntry) {
        return false;
    }

    MODULEENTRY32 mod32{};
    mod32.dwSize = sizeof(mod32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    for (Module32First(snap, &mod32); Module32Next(snap, &mod32);) {
        if (mod32.th32ProcessID != pid) {
            continue;
        }

        if (mod32.szModule == ModuleName) {
            *pEntry = mod32;
            break;
        }
    }

    CloseHandle(snap);

    return pEntry->modBaseAddr;
}

bool isFileExists(const std::string& name) {
    std::ifstream f(name.c_str());
    return f.good();
}

void LoadConfig() {
    if (isFileExists("fps-config.json")) {
        std::ifstream jsonFile;
        jsonFile.open("fps-config.json");

        std::stringstream strStream;
        strStream << jsonFile.rdbuf();
        std::string str = strStream.str();

        json jsonContent = json::parse(str);

        gamePath = jsonContent.value("game-path", R"(C:\\Program Files\\Genshin Impact\\Genshin Impact game\\GenshinImpact.exe)");
        targetFPS = jsonContent.value("target-fps", 60);

        jsonFile.close();
    } else {
        printf("Config file not found, please open Genshin Impact to create config!\n");
        printf("The game will exit and you need to run the program again\n\n");
        printf("Waiting for the game to open...\n");

        DWORD pid = 0;
        while (!(pid = FindProcessID("YuanShen.exe")) && !(pid = FindProcessID("GenshinImpact.exe"))) {
            Sleep(200);
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);

        char szPath[MAX_PATH]{};
        DWORD length = sizeof(szPath);
        QueryFullProcessImageNameA(hProcess, 0, szPath, &length);

        std::ofstream jsonFile("fps-config.json");

        json jsonContent;
        jsonContent["game-path"] = szPath;
        jsonContent["target-fps"] = 60;

        jsonFile << jsonContent;
        jsonFile.close();

        HWND hwnd = nullptr;
        while (!(hwnd = FindWindowA("UnityWndClass", nullptr))) {
            Sleep(200);
        }

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE) {
            SendMessageA(hwnd, WM_CLOSE, 0, 0);
            GetExitCodeProcess(hProcess, &ExitCode);
            Sleep(200);
        }

        WaitForSingleObject(hProcess, -1);
        CloseHandle(hProcess);

        system("cls");
    }
}

int main() {
    LoadConfig();

    printf("Launching Genshin Impact...\n");

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};

    if (!CreateProcessA(gamePath.c_str(), (LPSTR) "", nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi)) {
        DWORD code = GetLastError();
        printf("CreateProcess failed (%lu)", code);
        return 0;
    }

    CloseHandle(pi.hThread);

    printf("PID: %lu\n", pi.dwProcessId);

    MODULEENTRY32 hUnityPlayer{};
    while (!GetModule(pi.dwProcessId, "UnityPlayer.dll", &hUnityPlayer)) {
        Sleep(100);
    }

    LPVOID mem = VirtualAlloc(nullptr, hUnityPlayer.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        DWORD code = GetLastError();
        printf("VirtualAlloc failed (%lu)\n", code);
        return 0;
    }

    ReadProcessMemory(pi.hProcess, hUnityPlayer.modBaseAddr, mem, hUnityPlayer.modBaseSize, nullptr);

    printf("Finding pattern...\n");

    auto address = reinterpret_cast<uintptr_t>(PatternScan(mem, "7F 0F 8B 05 ? ? ? ?"));
    if (!address) {
        printf("Outdated pattern!\n");
        return 0;
    }

    uintptr_t pfps = 0;
    {
        uintptr_t rip = address + 2;
        uint32_t rel = *(uint32_t *) (rip + 2);
        pfps = rip + rel + 6;
        pfps -= (uintptr_t) mem;
        printf("FPS Offset: %llX\n", pfps);
        pfps = (uintptr_t) hUnityPlayer.modBaseAddr + pfps;
    }

    address = reinterpret_cast<uintptr_t>(PatternScan(mem, "E8 ? ? ? ? 8B E8 49 8B 1E"));
    uintptr_t pvsync = 0;
    if (address) {
        uintptr_t ppvsync = 0;
        uintptr_t rip = address;
        int32_t rel = *(int32_t *) (rip + 1);
        rip = rip + rel + 5;
        uint64_t rax = *(uint32_t *) (rip + 3);
        ppvsync = rip + rax + 7;
        ppvsync -= (uintptr_t) mem;
        printf("VSync Offset: %llX\n\n", ppvsync);
        ppvsync = (uintptr_t) hUnityPlayer.modBaseAddr + ppvsync;

        uintptr_t buffer = 0;
        while (!buffer) {
            ReadProcessMemory(pi.hProcess, (LPCVOID) ppvsync, &buffer, sizeof(buffer), nullptr);
            Sleep(100);
        }

        rip += 7;
        pvsync = *(uint32_t *) (rip + 2);
        pvsync = buffer + pvsync;
    }

    VirtualFree(mem, 0, MEM_RELEASE);

    printf("Target FPS: %d", targetFPS);

    int fps = 0;
    int vsync = 0;
    DWORD ExitCode = STILL_ACTIVE;

    while (ExitCode == STILL_ACTIVE) {
        GetExitCodeProcess(pi.hProcess, &ExitCode);

        Sleep(3000);

        ReadProcessMemory(pi.hProcess, (LPVOID) pfps, &fps, sizeof(fps), nullptr);
        if (fps == -1) {
            continue;
        }

        if (fps != targetFPS) {
            WriteProcessMemory(pi.hProcess, (LPVOID) pfps, &targetFPS, sizeof(targetFPS), nullptr);
        }

        ReadProcessMemory(pi.hProcess, (LPVOID) pvsync, &vsync, sizeof(vsync), nullptr);
        if (vsync) {
            vsync = 0;
            WriteProcessMemory(pi.hProcess, (LPVOID) pvsync, &vsync, sizeof(vsync), nullptr);
        }
    }

    WaitForSingleObject(pi.hProcess, -1);
    CloseHandle(pi.hProcess);
}