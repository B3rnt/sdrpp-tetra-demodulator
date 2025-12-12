#pragma once
#include <mutex>
#include <fstream>
#include <string>

class MmLog {
public:
    static MmLog& inst() {
        static MmLog s;
        return s;
    }

    void log(const std::string& line) {
        std::lock_guard<std::mutex> lk(m_);
        if (!ofs_.is_open()) {
            ofs_.open("tetra_mm.log", std::ios::out | std::ios::app);
        }
        if (ofs_.is_open()) {
            ofs_ << line << "\n";
            ofs_.flush();
        }
    }

private:
    MmLog() = default;
    std::mutex m_;
    std::ofstream ofs_;
};
