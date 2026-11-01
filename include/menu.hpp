#pragma once

#include <string>
#include <vector>

namespace XIII {

    struct MenuItem {
        std::string code;
        std::string title;
        std::string description;
    };

    class Menu {
    public:
        static void DisplayMainMenu();
        static int GetUserChoice();
        static void ExecuteOption(int option);
    };

} // namespace XIII
