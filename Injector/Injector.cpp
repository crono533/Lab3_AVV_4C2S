#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cout << "usage: Injector.exe <PID> <FullPathToDLL>" << std::endl;
        return 0;
    }

    DWORD dwProcessId = (DWORD)(atoi(argv[1]));

    const char* dllPath = argv[2];
    int dllPathSize = lstrlenA(dllPath) + 1; 

    // Открываем целевой процесс
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |    
        PROCESS_VM_OPERATION |     
        PROCESS_VM_WRITE,         
        FALSE,
        dwProcessId
    );

    if (!hProcess)
    {
        std::cerr << "OpenProcess failed. GetLastError: " << GetLastError() << std::endl;
        return 1;
    }

    // Выделяем память в целевом процессе под путь к DLL
    LPVOID pRemoteMem = VirtualAllocEx(
        hProcess,
        nullptr,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pRemoteMem)
    {
        std::cerr << "VirtualAllocEx failed. GetLastError: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Записываем путь к DLL в выделенную память
    SIZE_T bytesWritten;
    BOOL bWrite = WriteProcessMemory(
        hProcess,
        pRemoteMem,
        dllPath,
        dllPathSize,
        &bytesWritten
    );

    if (!bWrite || (bytesWritten != dllPathSize))
    {
        std::cerr << "WriteProcessMemory failed. GetLastError: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Получаем адрес LoadLibraryA из kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    if (!hKernel32)
    {
        std::cerr << "GetModuleHandleA(\"Kernel32\") failed. GetLastError: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA)
    {
        std::cerr << "GetProcAddress(LoadLibraryA) failed. GetLastError: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Создаём удалённый поток, который выполнит LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        pLoadLibraryA,
        pRemoteMem,
        0,
        nullptr
    );

    if (!hThread)
    {
        std::cerr << "CreateRemoteThread failed. GetLastError: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "DLL Injection successful!" << std::endl;
    return 0;
}
