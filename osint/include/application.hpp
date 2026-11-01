#pragma once

#include <string>
#include "menu.hpp"

namespace XIII {

    class Application {
    public:
        static Application& Instance();

        int Run(int argc, char* argv[]);
        void Shutdown();

    private:
        Application() = default;
        ~Application() = default;

        bool Initialize();
        void DisplayStartupSequence();
        bool ValidateLicenseOnStartup();
    };

} // namespace XIII
