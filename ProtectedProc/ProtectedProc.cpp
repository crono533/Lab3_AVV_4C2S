// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include <Windows.h>
#include <iostream>
#include <cstring>    // strcmp, lstrlenA
#include <cstdio>     // printf
#include <string>     // std::string
//Подключаем макросы для локальной защиты
#define LOCAL_BLOCKDLLPOLICY
#ifdef LOCAL_BLOCKDLLPOLICY
  // Аргумент командной строки, по которому понимаем, что процесс уже защищён в безопасном режиме
#define STOP_ARG "xakep"
#endif

// Функция создаёт новый процесс по lpProcessPath с политикой 
// блокирующей загрузку неподписанных Microsoftом библиотек
// При успехе возвращает 1 и заполняет dwProcessId hProcess hThread
BOOL CreateProcessWithBlockDllPolicy(
    LPCSTR            lpProcessPath,
    LPDWORD           pdwProcessId,
    LPHANDLE          phProcess,
    LPHANDLE          phThread)
{
    // 1) Подготовка STARTUPINFOEXA (расширенный STARTUPINFO)
    //STARTUPINFO - структура которая отвечает за запуск процессов в windows,
    // в ней можно укзаать множество аргументов, в том числе и флаги 
    // нам нужно запустить процесс с флагом PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY

    STARTUPINFOEXA siEx{ 0 };

    PROCESS_INFORMATION pi{ 0 };


    siEx.StartupInfo.cb = sizeof(siEx); //поле cb - count of bytes означает размер структуры в байтах

    // CreateProcessA что будем передавать расширенные атрибуты атрибуты, т.к. 
   // по стандарту стркута запуска процессов не смотрит в поле атрибутов или флагов при запуске
    //теперь будет
    siEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // 2) Определяем, какой размер буфера потребуется
    SIZE_T attrListSize = 0;
    // Первый вызов: получаем необходимый размер attrListSize
    InitializeProcThreadAttributeList(
        // указатель на буфер атрибутов, но pAttributeList — ещё не выделён
        // то есть, пока некуда записывать атрибут безопасности
        //поэтому первый параметр nullptr
        nullptr,              
        1,                    // будем задавать один атрибут
        0,                    // ?? (резервация чего то, должно быть 0)
        &attrListSize);       // получим нужный размер

    // 3) Выделяем память из кучи текущего процесса под список атрибутов
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(),     // дескриптор куча процесса
            HEAP_ZERO_MEMORY,     // флаг -  очистить память нулями
            attrListSize);        // размер в байтах

    if (!pAttrList)
        return FALSE;

    // 4) Первый вызов: Инициализируем список атрибутов
    if (!InitializeProcThreadAttributeList(
        pAttrList,        // куда (теперь есть)
        1,                // сколько атрибутов
        0,                // ?? (резервация чего то, должно быть 0)
        &attrListSize))   // размер буфера
    {
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // 5) Устанавливаем политику блокировки неподписанных Microsoftом бинарных файлов
    // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (!UpdateProcThreadAttribute(
        pAttrList,                              // наш список
        0,                                      // ?? (резервация чего то, должно быть 0)
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,// какой атрибут задаём
        &policy,                                // указатель на значение политики
        sizeof(policy),                         // размер данных
        nullptr,                                // значение старой политики
        nullptr))                               // размер старой политики
    {
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // 6) Привязываем наш список атрибутов к STARTUPINFOEXA
    siEx.lpAttributeList = pAttrList;

    // 7) Запускаем процесс
    BOOL ok = CreateProcessA(
        nullptr,              // lpApplicationName — nullptr т.к. путь передаём в строке
        (LPSTR)lpProcessPath, // lpCommandLine — cmd: путь + аргумент
        nullptr,              // lpProcessAttributes — дескриптор не наследуется(??)
        nullptr,              // lpThreadAttributes (??)
        FALSE,                // bInheritHandles — не наследуем дескрипторы (??)
        EXTENDED_STARTUPINFO_PRESENT, //флаг расширенного представления структуры запуска процессов
        nullptr,              // lpEnvironment — наследуем текущие env (??)
        nullptr,              // lpCurrentDirectory (??)
        &siEx.StartupInfo,    // наша расширенная стркутра
        &pi);                 // сюда вернутся hProcess, hThread, PID, TID

    // очистка того что создано
    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);

    if (!ok)
        return FALSE;

    // 8) Отдаём результаты в вызывающий код
    *pdwProcessId = pi.dwProcessId;
    *phProcess = pi.hProcess;
    *phThread = pi.hThread;
    return TRUE;
}

int main(int argc, char* argv[])
{
#ifdef LOCAL_BLOCKDLLPOLICY
    // Если ключ STOP_ARG есть в аргументах — значит программа  уже запущена
    // с политикой блокировки dll 
    if (argc == 2 && strcmp(argv[1], STOP_ARG) == 0)
    {
        printf("[+] Process is now protected with block-DLL policy.\n");
        
        WaitForSingleObject((HANDLE)-1, INFINITE);
        return 0;
    }
    else
    {
        printf("[!] Process is not protected. Restarting with block-DLL policy...\n");

        // Получаем полный путь к текущему exe
        CHAR modulePath[MAX_PATH];
        if (!GetModuleFileNameA(
            nullptr,                // стандартный модуль
            modulePath,             // буфер для пути
            MAX_PATH))              // размер буфера
        {
            printf("GetModuleFileNameA failed: %lu\n", GetLastError());
            return -1;
        }

        // Формируем командную строку "<полный путь до exe> + STOP_ARG"
        size_t cmdLen = lstrlenA(modulePath) + 1 + lstrlenA(STOP_ARG) + 1;
        CHAR* cmdline = (CHAR*)HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            cmdLen);

        if (!cmdline)
            return -1;

        //"C:\path\to\ProtectedProcess.exe xakep"
        sprintf_s(cmdline, cmdLen, "%s %s", modulePath, STOP_ARG);

        // Запускаем копию себя с политикой
        DWORD  newPid;
        HANDLE hNewProc, hNewThread;
        if (!CreateProcessWithBlockDllPolicy(
            cmdline, &newPid, &hNewProc, &hNewThread))
        {
            printf("Failed to create protected process: %lu\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, cmdline);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, cmdline);
        printf("[i] Protected process started. PID=%lu\n", newPid);

        char* str = new char[10];
        strcpy_s(str, 10, "Hello!");
        std::cout << str << std::endl;

        //delete []str;

        return 0;
    }
#else
    return 0;
#endif
}
