#pragma once
#include <Windows.h>
#include <stdio.h>

class ConsoleHandler {
public:
    static ConsoleHandler& Instance();
    static void Cleanup();
    static void Init();
    static void Destroy();

    bool Initialize();
    bool IsValid() const { return m_isValid; }

private:
    ConsoleHandler();
    ~ConsoleHandler();

    bool m_isValid;
    FILE* m_consoleFile;

    // «апрещаем копирование и присваивание
    ConsoleHandler(const ConsoleHandler&) = delete;
    ConsoleHandler& operator=(const ConsoleHandler&) = delete;

    static ConsoleHandler* s_instance;
    static CRITICAL_SECTION s_cs;
};