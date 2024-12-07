#include <stdafx.h>
#include "ConsoleHandler.h"

ConsoleHandler* ConsoleHandler::s_instance = nullptr;
CRITICAL_SECTION ConsoleHandler::s_cs;

void ConsoleHandler::Init() {
    InitializeCriticalSection(&s_cs);
}

void ConsoleHandler::Destroy() {
    DeleteCriticalSection(&s_cs);
}

ConsoleHandler::ConsoleHandler() : m_isValid(false), m_consoleFile(nullptr) {
}

ConsoleHandler::~ConsoleHandler() {
#ifdef _DEBUG
    if (m_consoleFile) {
        fclose(m_consoleFile);
        m_consoleFile = nullptr;
    }
    if (m_isValid) {
        FreeConsole();
        m_isValid = false;
    }
#endif
}

ConsoleHandler& ConsoleHandler::Instance() {
    if (!s_instance) {
        EnterCriticalSection(&s_cs);
        if (!s_instance) {
            s_instance = new ConsoleHandler();
        }
        LeaveCriticalSection(&s_cs);
    }
    return *s_instance;
}

void ConsoleHandler::Cleanup() {
    EnterCriticalSection(&s_cs);
    if (s_instance) {
        delete s_instance;
        s_instance = nullptr;
    }
    LeaveCriticalSection(&s_cs);
}

bool ConsoleHandler::Initialize() {
#ifdef _DEBUG
    if (m_isValid) return true;  // Уже инициализирован

    if (AllocConsole()) {
        // Открываем потоки для консоли
        if (freopen_s(&m_consoleFile, "CONOUT$", "w", stdout) != 0) {
            return false;
        }
        if (freopen_s(&m_consoleFile, "CONOUT$", "w", stderr) != 0) {
            return false;
        }
        if (freopen_s(&m_consoleFile, "CONIN$", "r", stdin) != 0) {
            return false;
        }

        // Настраиваем поддержку ANSI escape sequences
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if (SetConsoleMode(hOut, dwMode)) {
                    m_isValid = true;
                    return true;
                }
            }
        }
    }
#endif
    return false;
}