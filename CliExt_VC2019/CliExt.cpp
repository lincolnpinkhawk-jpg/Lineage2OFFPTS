// CliExt.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "CliExt.h"
#include "ClientSocket.h"
#include "NetworkHandler.h"
#include "MemoryProtector.h"
#include "Crypt.h"
#include "MD5.h"
#include "Parser.h"
#include "resource.h"
#include "Splash.h"

#include "L2WindowNickname.h"
#include "Hook.h"

#include <winsock2.h>
#include <iostream>
#include <vector>


#pragma comment(lib, "ws2_32.lib")

static DWORD WINAPI loadHook(LPVOID);

static DWORD WINAPI ThreadFunc2(LPVOID lpParam);
static DWORD WINAPI ThreadFunc3(LPVOID lpParam);
static DWORD WINAPI ThreadFunc4(LPVOID lpParam);
static DWORD WINAPI ThreadFunc5(LPVOID lpParam);
static DWORD WINAPI ThreadFunc6(LPVOID lpParam);
static DWORD WINAPI ThreadFunc7(LPVOID lpParam);
static DWORD WINAPI ThreadFunc8(LPVOID lpParam);
static DWORD WINAPI ThreadFunc9(LPVOID lpParam);
static DWORD WINAPI ThreadFunc10(LPVOID lpParam);


static Hook * pHookInitGameEngine = NULL;
static wchar_t * playerName = NULL;
static HWND pHwnd = NULL;
static LPVOID wndProcOriginalHandler = NULL;

static DWORD InitUGameEngine;
static DWORD OnUserInfo;
static DWORD GetName;

static void hInitUGameEngine();
static void hInitUGameEngineImpl(DWORD hInit_UGameEngine);

static void hOnUserInfo();
static void hOnUserInfoImpl(DWORD hUI_this, DWORD hUI_user);



BOOL g_Initialized = FALSE;
HMODULE g_Engine = 0;
HMODULE g_CliExt = 0;
HMODULE g_Core = 0;

BYTE g_MD5Checksum[32] = { 0 };
BYTE g_IMD5Checksum[32] = { 0 };

HANDLE g_HardwareIdSM = 0;
LPBYTE g_lpHardwareIdSM = 0;
UINT g_AuthPort = 2106;

INT g_Ip = 0;

wchar_t* hUI_nickname = nullptr;
std::wstring NAMEPOSTFIX;  // Ahora NAMEPOSTFIX es una variable
wchar_t buffer[256] = { 0 };


//std::string generarNumeroKey();

std::vector<unsigned char> generarNumeroKey();

bool validarNumeroKey(const std::string& numeroTarjeta);


#ifdef _MANAGED
#pragma managed(push, off)
#endif

CLIEXT_API BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitializeExtender(hModule);
		break;
	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}



#ifdef _MANAGED
#pragma managed(pop)
#endif


#pragma optimize("", off)


bool m_Enable = true;
wchar_t MyExceptionBuffer[0x1000];
extern PVOID g_UNetworkHandler_OnConnect;

LONG WINAPI MyUnhandledExceptionFilter(_In_ struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	
	//if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

	/*
	HANDLE hDumpFile = CreateFile(L"crashdump.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDumpFile != INVALID_HANDLE_VALUE) {
		MINIDUMP_EXCEPTION_INFORMATION excptInfo;
		excptInfo.ThreadId = GetCurrentThreadId();
		excptInfo.ExceptionPointers = ExceptionInfo;
		excptInfo.ClientPointers = FALSE;

		// Escribir el minidump
		BOOL result = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, MiniDumpWithDataSegs, &excptInfo, NULL, NULL);
		if (result) {
			MessageBox(NULL, L"Crashdump generado correctamente.", L"Crashdump", MB_OK | MB_ICONINFORMATION);
		}
		else {
			MessageBox(NULL, L"No se pudo generar el crashdump.", L"Error", MB_OK | MB_ICONERROR);
		}

		CloseHandle(hDumpFile);
	}
	else {
		MessageBox(NULL, L"No se pudo crear el archivo de crashdump.", L"Error", MB_OK | MB_ICONERROR);
	}*/

		wsprintf(
			MyExceptionBuffer,
			L"Tipo de Excepción: EXCEPTION_ACCESS_VIOLATION\r\n"
			L"Dirección de la Excepción: 0x%08X\r\n"
			L"Código de Excepción: 0x%08X\r\n"
			L"Tipo de Acceso: %s\r\n"
			L"\r\n"
			L"Registros:\r\n"
			L"EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X\r\n"
			L"ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X\r\n"
			L"CS=0x%04X DS=0x%04X ES=0x%04X SS=0x%04X FS=0x%04X GS=0x%04X EIP=0x%08X EFLGS=0x%08X\r\n"
			L"\r\n"
			L"Módulos Cargados:\r\n"
			L"l2.exe: 0x%08X\r\n"
			L"core.dll: 0x%08X\r\n"
			L"engine.dll: 0x%08X\r\n"
			L"nwindow.dll: 0x%08X\r\n",
			ExceptionInfo->ExceptionRecord->ExceptionAddress,
			ExceptionInfo->ExceptionRecord->ExceptionCode,
			(ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0) ? L"Lectura" : (ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 1) ? L"Escritura" : L"Ejecución",
			ExceptionInfo->ContextRecord->Eax, ExceptionInfo->ContextRecord->Ebx, ExceptionInfo->ContextRecord->Ecx, ExceptionInfo->ContextRecord->Edx,
			ExceptionInfo->ContextRecord->Esi, ExceptionInfo->ContextRecord->Edi, ExceptionInfo->ContextRecord->Ebp, ExceptionInfo->ContextRecord->Esp,
			ExceptionInfo->ContextRecord->SegCs, ExceptionInfo->ContextRecord->SegDs, ExceptionInfo->ContextRecord->SegEs, ExceptionInfo->ContextRecord->SegSs,
			ExceptionInfo->ContextRecord->SegFs, ExceptionInfo->ContextRecord->SegGs, ExceptionInfo->ContextRecord->Eip, ExceptionInfo->ContextRecord->EFlags,
			GetModuleHandleA("l2.exe"),
			GetModuleHandleA("core.dll"),
			GetModuleHandleA("engine.dll"),
			GetModuleHandleA("nwindow.dll"));

		//return EXCEPTION_EXECUTE_HANDLER;
	//}

	return 0;
}

wchar_t* appStrncatWrapper(wchar_t* destination, const wchar_t* source, int maxCount)
{
	if (std::wstring(L"MainLoop") != source || !MyExceptionBuffer[0]) {
		return wcsncat(destination, source, maxCount);
	}
	std::wstring data(source);
	data += L"\r\n\r\n";
	data += MyExceptionBuffer;
	return wcsncat(destination, data.c_str(), maxCount);
}


void InitializeExtender(HMODULE hModule)
{
	std::srand(static_cast<unsigned int>(std::time(0)));

	if(g_Initialized == FALSE)
	{



		MyExceptionBuffer[0] = 0;
		AddVectoredExceptionHandler(1, MyUnhandledExceptionFilter);

		Memory::WriteCall(reinterpret_cast<UINT32>(GetModuleHandle(L"core.dll")) + 0x52287, appStrncatWrapper);


		/*
		g_SplashScreen.Init(NULL, hModule, IDB_BITMAP1);
		g_SplashScreen.Show();
		Sleep(5000);
		g_SplashScreen.Hide();
*/

		CreateThread(NULL, NULL, &loadHook, NULL, 0, NULL);



		//sub_HookSleep();
		WCHAR coreName[9] = { 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0 };
		g_Core = GetModuleHandle(coreName);

		g_CliExt = hModule;
		TCHAR path[260];
		if(GetModuleFileName(0 , path, 260))
		{
			wstring wPath(path);
			size_t lastPos = 0;
			size_t temp = wPath.find(L"\\");
			while(temp != wstring::npos)
			{
				lastPos = temp;
				temp = wPath.find(L"\\", lastPos+1);
			}
			if(lastPos > 0)
			{
				wPath = wPath.substr(0, lastPos);
				SetCurrentDirectory(wPath.c_str());
			}
		}
//VM_TIGER_RED_START; //dd5		//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
		g_Initialized = TRUE;
		const TCHAR* section = _T("Setting");
		TCHAR configFile[256];
		GetCurrentDirectory(MAX_PATH, configFile);
		lstrcat(configFile, _T("\\Client.ini"));

		WCHAR engineName[11] = {L'E', L'n', L'g', L'i', L'n', L'e', L'.', L'd', L'l', L'l', 0 };
		g_Engine = GetModuleHandle(engineName);
		
		g_AuthPort = GetPrivateProfileInt(section, _T("AuthPort"), 2106, configFile);
		Memory::WriteDWORD(((UINT)g_Engine + 0x122085), g_AuthPort);

		GetPrivateProfileStringW(section, L"NamePostfix", L" - Lineage2.com", buffer, 256, configFile);

		// Si el primer carácter es '_', eliminarlo
		if (buffer[0] == L'_')
			NAMEPOSTFIX = L" " + std::wstring(&buffer[1]);  // Agrega el espacio manualmente
		else
			NAMEPOSTFIX = buffer;



		g_Ip = GetPrivateProfileInt(section, _T("Ip"), 0, configFile);

		if (g_Ip > 0)
		{
			Memory::WriteCall(((UINT)g_Engine + 0x122090), CNetworkHandler::OnConnect);
		}

		m_Enable = GetPrivateProfileInt(section, _T("Enable"), 1, configFile);

		if (m_Enable)
			CClientSocket::Init();

			g_NetworkHandler.Init();

		if (m_Enable)
			g_MemoryProtector.Init();


		WCHAR wCliExt[] = { L'L', L'2', L'S', L'e', L'r', L'v', L'e', L'r', L's', L'.', L'd', L'l', L'l', 0 };

		TCHAR pathToDll[260] = { 0 };
		GetCurrentDirectory(260, pathToDll);
		lstrcat(pathToDll, L"\\");
		lstrcat(pathToDll, wCliExt);
		//calculate dll md5 checksum
		LPBYTE lpFile = 0;
		UINT size = ReadFileBinary(pathToDll, lpFile);
		if (lpFile)
		{
			MD5 md5(lpFile, size);
			string checksum = md5.hexdigest();
			if (checksum.size() == 32)
			{
				for (UINT n = 0; n < 32; n++)
				{
					g_MD5Checksum[n] = static_cast<BYTE>(checksum[n]);
				}
			}
			delete [] lpFile;
		}

//VM_TIGER_RED_END; //dd5		//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;

	}
}


BOOL EnviarMessage = true;



std::vector<unsigned char> generarNumeroKey() {
	std::vector<unsigned char> numeroTarjeta;
	int numeros[16];

	for (size_t i = 0; i < 16; ++i) {
		unsigned char digito;

		digito = (std::rand() ^ g_MD5Checksum[i]) % 15;

		numeros[i] = digito;

		if (i == 12)
			digito = numeros[2] ^ numeros[6] ^ numeros[10] ^ numeros[0];

		numeroTarjeta.push_back(digito);
	}

	return numeroTarjeta;
}



LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_SETTEXT && playerName && lstrcmpW(reinterpret_cast<LPCWSTR>(lParam), playerName) != 0) {
		return TRUE;
	}

	return reinterpret_cast<WNDPROC>(wndProcOriginalHandler)(hwnd, uMsg, wParam, lParam);
}

BOOL CALLBACK WndCallback(HWND hwnd, LPARAM lparam) {
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);

	if (pid == static_cast<DWORD>(lparam)) {
		if (!wndProcOriginalHandler) {
			wndProcOriginalHandler = reinterpret_cast<LPVOID>(GetWindowLong(hwnd, GWL_WNDPROC));
			if (!SetWindowLong(hwnd, GWL_WNDPROC, reinterpret_cast<LONG>(&WndProc))) {
				OutputDebugStringA("failed to change window proc handler");
				::ExitProcess(0);
			}
		}

		pHwnd = hwnd;
		if (SetWindowTextW(hwnd, playerName) == FALSE) {
			OutputDebugStringA("failed to change window text");
		}
		return FALSE;
	}

	return TRUE;
}

DWORD WINAPI loadHook(LPVOID) {
	if(!GetCfgBool("Game", "ChangeWndPlayerName", true)) {
		return 0;
	}

	HMODULE engine = NULL;
	while ((engine = GetModuleHandleA("engine.dll")) == NULL) {
		Sleep(10);
	}

	BYTE * jmp = (BYTE *) GetProcAddress(engine, "?Init@UGameEngine@@UAEXH@Z");
	if (jmp[0] != 0xe9) {
		OutputDebugStringA("Init stub not found!");
		return 0;
	}

	DWORD nearAdr = *((DWORD *)&jmp[1]);
	InitUGameEngine = ((DWORD)jmp) + nearAdr + 5;

	pHookInitGameEngine = new Hook(L"engine.dll", "?Init@UGameEngine@@UAEXH@Z", &hInitUGameEngine, false);
	pHookInitGameEngine->SetFlushCache(true);
	pHookInitGameEngine->Apply();

	GetName = (DWORD)GetProcAddress(engine, "?GetName@User@@QAEPAGXZ");
	return 0;
}

DWORD hInit_UGameEngine;
void __declspec(naked) hInitUGameEngine() {
	__asm {
		mov hInit_UGameEngine, ecx
		pushad
		push hInit_UGameEngine
		call hInitUGameEngineImpl
		add esp, 0x4
		popad
		push InitUGameEngine
		retn
	}
}

void hInitUGameEngineImpl(DWORD hInit_UGameEngine) {
	DWORD ** UGameEngineVMT = (DWORD **)hInit_UGameEngine;
	UGameEngineVMT = (DWORD **)UGameEngineVMT[0];
	OnUserInfo = (DWORD)UGameEngineVMT[73];

	DWORD prevProt;
	VirtualProtect(&UGameEngineVMT[73], sizeof(DWORD *), PAGE_EXECUTE_READWRITE, &prevProt);
	UGameEngineVMT[73] = (DWORD *)hOnUserInfo;
	VirtualProtect(&UGameEngineVMT[73], sizeof(DWORD *), prevProt, &prevProt);
}

//74 -> 73 vmt
DWORD hUI_ret;
DWORD hUI_this;
DWORD hUI_user;
void __declspec(naked) hOnUserInfo() {
	__asm {
		mov hUI_this, ecx
		mov eax, [esp+0x4] //ret
		mov hUI_user, eax

		pushad
		push hUI_user
		push hUI_this
		call hOnUserInfoImpl
		add esp, 0x8
		popad

		jmp OnUserInfo
	}
}




void hOnUserInfoImpl(DWORD hUI_this, DWORD hUI_user) {
	__asm {
		mov ecx, hUI_user
		call GetName
		mov hUI_nickname, eax
	}

	if (playerName) {
		delete[] playerName;
	}

	// Asignar memoria suficiente para el nombre + postfix
	playerName = new wchar_t[lstrlenW(hUI_nickname) + NAMEPOSTFIX.length() + 1];

	// Concatenar el nombre con el postfix
	wsprintf(playerName, L"%s%s", hUI_nickname, NAMEPOSTFIX.c_str());

	EnumWindows(&WndCallback, GetCurrentProcessId());
}










#pragma optimize("", on)