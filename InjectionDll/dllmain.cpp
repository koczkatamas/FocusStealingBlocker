// dllmain.cpp : Defines the entry point for the DLL application.
#define WIN32_LEAN_AND_MEAN
#include "stdafx.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <memory>
#include <vector>

#include "MinHook/MinHook.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
//#pragma comment (lib, "AdvApi32.lib")

BOOL __stdcall MySetForegroundWindow(HWND hWnd) {
	//MessageBoxA(0, "MySetForegroundWindow", "InjectionDll", 0);
	return FlashWindow(hWnd, false);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	int result = 0;
	MH_STATUS createResult, enableResult;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MH_Initialize();
		////char buf[256];
		createResult = MH_CreateHook(SetForegroundWindow, MySetForegroundWindow, NULL);
		enableResult = MH_EnableHook(MH_ALL_HOOKS);
		//sprintf_s(buf, "createResult = %d, enableResult = %d", createResult, enableResult);
		//MessageBoxA(0, buf, "InjectionDll", 0);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		MH_Uninitialize();
		break;
	}
	return TRUE;
}