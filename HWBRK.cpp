#include "main.h"


LONG __stdcall hwbrkHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP || ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		for each(HWBRKEntry entry in *HWBRK->Hooks())
		{
			if(entry.targetFunction == ExceptionInfo->ContextRecord->Eip)
			{
				ExceptionInfo->ContextRecord->Eip = static_cast<DWORD>(entry.hook);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void *__fastcall hkBaseThreadInitThunk(ULONG Unknown, PVOID StartAddress, PVOID ThreadParameter)
{
	HANDLE	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
	if(hThread)
	{
		HWBRK->RefreshHooks(hThread);
		CloseHandle(hThread);
	}

	return HWBRK->BaseThreadInitThunk() (Unknown, StartAddress, ThreadParameter);
}



int CHWBRK::GetFreeIndex(size_t regValue)
{
	if(!(regValue & 1))
		return 0;
	else if(!(regValue & 4))
		return 1;
	else if(!(regValue & 16))
		return 2;
	else if(!(regValue & 64))
		return 3;

	return -1;
}

std::vector< HWBRKEntry > *CHWBRK::Hooks()
{
	return &this->m_hooks;
}

tBaseThreadInitThunk CHWBRK::BaseThreadInitThunk()
{
	return this->m_oBaseThreadInitThunk;
}


bool CHWBRK::HookThread(HANDLE thread, HWBRKEntry entry)
{
	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if(!GetThreadContext(thread, &context))
	{
		CloseHandle(thread);
		return false;
	}

	for(int i = 0; i < 4; i++)
	{
		if(*((size_t*)&context.Dr0 + i) == (size_t)entry.targetFunction)
		{
			return false; //function already hooked
		}
	}

	int index = this->GetFreeIndex(context.Dr7);
	if(index < 0)
	{
		return false;
	}

	context.Dr7 |= 1 << (2 * index) | 0x100;                                // enable corresponding HWBP and local BP flag 
	*((size_t*)&context.Dr0 + index) = (size_t)entry.targetFunction;        // write address to DR0-DR3 

	// Suspend thread
	DWORD suspendTime = 0x1337;
	bool ret = true;
	if(GetThreadId(thread) != GetCurrentThreadId())
	{
		suspendTime = SuspendThread(thread);
	}

	// Write values to registers 
	if(!SetThreadContext(thread, &context))
	{
		ret = false;
	}


	if(suspendTime <= 0)
	{
		ResumeThread(thread);
	}

	return ret;
}

void CHWBRK::RefreshHooks(HANDLE hThread)
{
	//add every hook to debug register
	for each(HWBRKEntry entry in this->m_hooks)
	{
		this->HookThread(hThread, entry);
	}
}

void CHWBRK::RefreshHooks()
{
	DWORD processId = GetCurrentProcessId();
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if(Thread32First(h, &te))
		{
			do
			{
				if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == processId)
				{
					//Thread belongs to our process

					if(te.th32ThreadID == GetCurrentThreadId())
					{
						continue;
					}
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

					if(hThread)
					{
						this->RefreshHooks(hThread);
						CloseHandle(hThread);
					}
				}
				te.dwSize = sizeof(te);
			} while(Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}

void CHWBRK::AddHook(DWORD_PTR targetFunction, DWORD_PTR hook)
{
	HWBRKEntry newEntry;
	newEntry.hook = hook;
	newEntry.targetFunction = targetFunction;
	this->m_hooks.push_back(newEntry);

	if(this->m_hooks.size() > 4)
	{
		throw new std::runtime_error("Too many hooks registered");
	}

	this->RefreshHooks();
}

CHWBRK::CHWBRK()
{
	this->m_hooks = std::vector<HWBRKEntry>();
	this->m_handlerHandle = AddVectoredExceptionHandler(TRUE, hwbrkHandler);

	byte *pBaseThreadInitThunk = reinterpret_cast<byte*>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk"));
	this->m_oBaseThreadInitThunk = reinterpret_cast<tBaseThreadInitThunk>(DetourFunction(pBaseThreadInitThunk, reinterpret_cast<byte*>(hkBaseThreadInitThunk)));
}

CHWBRK::~CHWBRK()
{

	this->m_hooks.clear();
	this->RefreshHooks();

	if(this->m_oBaseThreadInitThunk)
	{
		//DetourRemove ( )
	}

	if(this->m_handlerHandle)
	{
		RemoveVectoredExceptionHandler(this->m_handlerHandle);
	}
}

CHWBRK *HWBRK = nullptr;