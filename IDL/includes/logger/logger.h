#pragma once

#ifndef LOGGER_H 
#define LOGGER_H

#include <iostream>
#include <cstdio>
#include <cstdarg>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>

class Logger {
public:
    enum class LogLevel {
        ERR,
        WARNING,
        INFO,
        DEBUG
    };

    static void log(LogLevel level, const char* format, ...) {
        const auto now = std::chrono::system_clock::now();
        const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count() % 1000;

        const auto nowTime = std::chrono::system_clock::to_time_t(now);

        std::ostringstream timestamp;
        timestamp << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
        timestamp << '.' << std::setfill('0') << std::setw(3) << nowMs;

        const char* color = "";
        const char* prefix = "";
        switch (level) {
        case LogLevel::ERR:
            color = "\x1b[31m";  // red
            prefix = "ERROR";
            break;
        case LogLevel::WARNING:
            color = "\x1b[38;5;209m";  // peach
            prefix = "WARNING";
            break;
        case LogLevel::INFO:
            color = "\x1b[38;5;119m";  // lime
            prefix = "INFO";
            break;
        case LogLevel::DEBUG:
            color = "\x1b[38;5;218m";  // pink
            prefix = "DEBUG";
            break;
        }

        printf("%s[%s] %s[%s]:\x1b[0m ",
            color,
            timestamp.str().c_str(),
            color,
            prefix
        );


        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);

        printf("\n");
    }

    // Безопасная версия для std::string
    template<typename... Args>
    static void logs(LogLevel level, const std::string& format, Args... args) {
        log(level, format.c_str(), args...);
    }
};

// Макросы для удобного использования
#define LOG_ERROR(format, ...) Logger::log(Logger::LogLevel::ERR, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) Logger::log(Logger::LogLevel::WARNING, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) Logger::log(Logger::LogLevel::INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) Logger::log(Logger::LogLevel::DEBUG, format, ##__VA_ARGS__)

// Макросы для работы со std::string
#define LOG_ERROR_S(format, ...) Logger::logs(Logger::LogLevel::ERR, format, ##__VA_ARGS__)
#define LOG_WARN_S(format, ...) Logger::logs(Logger::LogLevel::WARNING, format, ##__VA_ARGS__)
#define LOG_INFO_S(format, ...) Logger::logs(Logger::LogLevel::INFO, format, ##__VA_ARGS__)
#define LOG_DEBUG_S(format, ...) Logger::logs(Logger::LogLevel::DEBUG, format, ##__VA_ARGS__)

#endif