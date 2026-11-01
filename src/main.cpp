#include "application.hpp"
#include <windows.h>
#include <iostream>

int main(int argc, char* argv[]) {
    // Windows Exception Handling wrapper
    try {
        return XIII::Application::Instance().Run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "\n[!] Fatal runtime exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n[!] Unhandled exception caught." << std::endl;
        return 1;
    }
}
