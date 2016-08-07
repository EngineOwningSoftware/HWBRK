#pragma once
#include "main.h"

typedef void *(__fastcall *tBaseThreadInitThunk)(ULONG Unknown, PVOID StartAddress, PVOID ThreadParameter);

struct HWBRKEntry
{
	DWORD_PTR targetFunction;
	DWORD_PTR hook;
};


class CHWBRK
{

private:

	int GetFreeIndex(size_t regValue);

	bool HookThread(HANDLE thread, HWBRKEntry context);

public:

	CHWBRK();

	~CHWBRK();

	void AddHook(DWORD_PTR targetFunction, DWORD_PTR hook);

	tBaseThreadInitThunk BaseThreadInitThunk();

	void RefreshHooks();

	void RefreshHooks(HANDLE hThread);

	std::vector< HWBRKEntry > *Hooks();

private:

	std::vector< HWBRKEntry > m_hooks;

	PVOID m_handlerHandle;

	tBaseThreadInitThunk m_oBaseThreadInitThunk;

};

extern CHWBRK *HWBRK;