#include <Windows.h>
#include <iostream>

int main()
{
    std::cout << "Target process started. PID: " << GetCurrentProcessId() << std::endl;

    std::cin.get();
    return 0;
}
