
#include "pch.h"
#include <Windows.h>  
#include <psapi.h>   // Библиотека позволяющая работать с информацией о процессах тут исп GetModuleBaseNameA
#include <iostream>
#include <cstdio>


void WriteLog(const char* text)
{
    FILE* f = fopen("C:\\Users\\disan\\Desktop\\Lab_3\\injection_log.txt", "a");
    if (!f)
    {
        MessageBoxA(NULL, "Failed to open log file", "Error", MB_OK);
        return;
    }
    fprintf(f, "%s\n", text);
    fclose(f);
}


void AttackProcess()
{
    char szProcessName[MAX_PATH] = { 0 };

    // GetModuleBaseNameA - получаем имя .exe-файла процесса, в котором мы находимся
    // 1 "GetCurrentProcess()" – получить дескриптор текущего процесса
    // 2 NULL – нам не нужен конкретно другой модуль, берём основной (просто имя процесса)
    // 3 szProcessName – куда будем записывать результат (имя процесса)
    //4 размер буфера
    GetModuleBaseNameA(GetCurrentProcess(), NULL, szProcessName, sizeof(szProcessName));
        // Попробуем вывести что-то в консоль
        std::cout << "Hello from injected DLL!\n";
        WriteLog("Injected");
}

// fdwReason    – причина вызова (DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH).
// lpvReserved  – зарезервированное значение, редко используем.
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, //когда загружается dll системв дает ему HINSTANCE (какой то идентификатор)
    DWORD fdwReason, //при вызове присваивается номер вызова (макрос)
    LPVOID lpvReserved // указатель на участок памяти который может содержать доп информацию о каждом вызове
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Срабатывает, когда библиотека впервые загружена в процесс
        AttackProcess();
        break;

    case DLL_THREAD_ATTACH:
        // Срабатывает когда в процессе создаётся новый поток
        break;

    case DLL_THREAD_DETACH:
        // Срабатывает когда поток завершается
        break;

    case DLL_PROCESS_DETACH:
        // Срабатывает когда процесс выгружает DLL (при закрытии процесса)
        break;
    }

    return TRUE;
}
