// Autobahn Raser 2 Spelfix!
#include "main.h"
#include <wchar.h>
#include <string>
#include <map>
#include <assert.h>

inline bool DoesFileExist( const char *name )
{
    return ( GetFileAttributes( name ) != INVALID_FILE_ATTRIBUTES );
}

inline std::wstring GetDirectoryFromFilePath( const std::wstring& filePath )
{
    size_t dirStart = 0;
    size_t dirEnd = 0;
    {
        size_t lastSeparator = 0;
       
        size_t n = 0;

        for ( std::wstring::const_iterator iter = filePath.begin(); iter != filePath.end(); ++iter )
        {
            wchar_t theChar = *iter;

            if ( theChar == L'/' || theChar == L'\\' )
            {
                lastSeparator = n;
            }

            n++;
        }

        dirEnd = lastSeparator;
    }
    return filePath.substr( dirStart, dirEnd );
}

std::string GetCurrentDirectoryString( void )
{
    DWORD requiredSize = GetCurrentDirectoryA( 0, NULL );

    std::string outString( requiredSize, (char)0 );

    DWORD numWrite = GetCurrentDirectoryA( requiredSize, (char*)outString.c_str() );

    assert( requiredSize == numWrite );

    return outString;
}

bool GetExecutablePath( std::string& resultPath )
{
    bool hasResultPath = false;
    {
        // Attempt to find the file in the current directory.
        const char *findFileName = "spel.exe";
        
        if ( !hasResultPath )
        {
            std::string curDirAbsPath;

            curDirAbsPath += GetCurrentDirectoryString();
            curDirAbsPath += "\\";
            curDirAbsPath += findFileName;

            if ( DoesFileExist( curDirAbsPath.c_str() ) == true )
            {
                resultPath = curDirAbsPath;

                hasResultPath = true;
            }
        }

        // Fetch the executable path from the registry.
        if ( !hasResultPath )
        {
            HKEY autobahnRaserKey;

            LONG keyOpenResult = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Davilex\\Autobahn Raser II\\1\\DE",
                0, KEY_READ, &autobahnRaserKey
            );

            if ( keyOpenResult == ERROR_SUCCESS )
            {
                wchar_t programPath[ 1024 ];
                DWORD bufferSize = sizeof( programPath );

                // This logic is not entirely correct, but meh.

                // Get the field which tells us about the main executable.
                LONG keyValueRequestResult = RegGetValueW(
                    autobahnRaserKey, NULL,
                    L"ProgramFile", RRF_RT_REG_SZ,
                    NULL, programPath, &bufferSize
                );

                if ( keyValueRequestResult == ERROR_SUCCESS )
                {
                    // Transform the given path to a directory path and append our program name to it.
                }
            }
        }
    }
	return hasResultPath;
}

const char* GetExecutableCurrentDirectory()
{
	return "C:/Programme/Davilex/Autobahn Raser II/";
}

const char* GetLibraryPath()
{
#ifdef _DEBUG
	return "\\spelfix\\core_d.dll";
#else
	return "\\spelfix\\core.dll";
#endif
}

#pragma warning(disable: 4996)

struct EnvironmentBlock
{
    EnvironmentBlock( wchar_t *envBlock )
    {
        while ( size_t len = wcslen( envBlock ) )
        {
            wchar_t *seperator = envBlock;

            while ( *seperator && *seperator != L'=' )
                seperator++;

            variables[std::wstring( envBlock, seperator )] = std::wstring( seperator + 1, envBlock + len );

            envBlock += len + 1;

            if ( *envBlock == L'\0' )
                break;
        }
    }

    std::wstring Get( const std::wstring& key )
    {
        variables_t::const_iterator iter = variables.find( key );

        if ( iter == variables.end() )
            return L"";

        return iter->second;
    }

    wchar_t* MakeTraverse( void )
    {
        size_t wtotallen = 1;

        for ( variables_t::const_iterator iter = variables.begin(); iter != variables.end(); iter++ )
        {
            wtotallen += iter->first.size() + iter->second.size() + 2;
        }

        wchar_t *envBlock = new wchar_t[wtotallen];
        wchar_t *cursor = envBlock;

        for ( variables_t::const_iterator iter = variables.begin(); iter != variables.end(); iter++ )
        {
            size_t len = iter->first.size();
            wcsncpy( cursor, iter->first.c_str(), len );
            cursor += len;

            *cursor++ = L'=';

            len = iter->second.size();
            wcsncpy( cursor, iter->second.c_str(), len );
            cursor += len;

            *cursor++ = L'\0';
        }

        *cursor++ = L'\0';

        return envBlock;
    }

    typedef std::map <std::wstring, std::wstring> variables_t;
    variables_t variables;
};

static char *environPointers = NULL;

inline std::wstring Convert( const char *str )
{
    size_t len = strlen( str );
    size_t wlen = MultiByteToWideChar( CP_UTF8, 0, str, (int)len, NULL, 0 );

    std::wstring wstr( wlen, L'0' );

    MultiByteToWideChar( CP_UTF8, 0, str, (int)len, (LPWSTR)wstr.c_str(), wlen );
    return wstr;
}

wchar_t* MakeEnvironment( void )
{
	// Grab newest environment variables
	wchar_t *envBlockPointers;
	HANDLE myToken = NULL;

	OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS, &myToken );

	CreateEnvironmentBlock( (LPVOID*)&envBlockPointers, myToken, 0 );

    EnvironmentBlock block( envBlockPointers );

	// Add the current directory to our path.
    char myDir[1024];
    GetCurrentDirectory( sizeof(myDir), myDir );

    std::wstring dirEnv = Convert( myDir );

    std::wstring pathVar = block.Get( L"Path" );
    pathVar += L";" + dirEnv + L";";
    block.variables[L"Path"] = pathVar;

	CloseHandle( myToken );
	DestroyEnvironmentBlock( envBlockPointers );

    return block.MakeTraverse();
}

wchar_t tempUnicodeBuffer[ 1024 ];

#define NUMELMS(a)	( sizeof(a) / sizeof(*a) )

inline HMODULE GetModuleHandleRemote( HANDLE hRemoteProcess, const char *moduleName )
{
	HMODULE resultModule = NULL;
	{
		HMODULE processModuleArray[ 256 ];
		DWORD writtenBytes = 0;

		BOOL success = EnumProcessModules( hRemoteProcess, processModuleArray, sizeof( processModuleArray ), &writtenBytes );
		
		DWORD lastError = GetLastError();

		if ( success == TRUE )
		{
			// Iterate through all modules
			unsigned int moduleCount = (unsigned int)( writtenBytes / sizeof(HMODULE) );

			for ( unsigned int n = 0; n < moduleCount; n++ )
			{
				HMODULE thisModule = processModuleArray[ n ];

				// Get the module name.
				BOOL getSuccess = GetModuleFileNameExW( hRemoteProcess, thisModule, tempUnicodeBuffer, NUMELMS( tempUnicodeBuffer ) );

				if ( getSuccess == TRUE )
				{
					__asm int 3
				}
			}
		}
	}
	return resultModule;
}

static void GetApplicationInitializationShellCode( void*& ptrToCodeOut, size_t& codeSizeOut )
{
	__asm
	{
		mov edx,[ptrToCodeOut]
		mov ecx,[codeSizeOut]

		mov eax,offset codeBegin
		mov ebx,offset codeEnd
		sub ebx,eax
		mov dword ptr [edx],eax
		mov dword ptr [ecx],ebx
		jmp codeEnd

codeBegin:
		// This shellcode is called as new process entry point.
		mov eax,0xCAFEBABE		// overwrite this with the old entry point.
		pushad

		// TODO: get pointer to kernel32.dll and its GetProcAddress routine automatically!

		// Change the current directory
		mov eax,0xBABECAFE		// pointer to SetCurrentDirectoryA
		mov ecx,0xBACAFEFE		// pointer to the application path (data only)
		push ecx
		call eax

		// If we are debugging, wait for the debugger.
#ifdef _DEBUG
		mov ebx,0xCAFEBABA
repeatUntilDebug:
		call ebx
		test eax,eax
		jz repeatUntilDebug
#endif

		// Load the game library
		mov eax,0xBABEBABE		// pointer to LoadLibraryA function
		mov ecx,0xCAFECAFE		// pointer to library path (data only)
		push ecx
		call eax

		// We are finished, proceed starting the application!

		popad
		call eax

		// TODO: unload the game library again.
		ret
codeEnd:
	}
}

template <typename dataType>
inline void MemPutOffset( void *ptr, size_t offset, const dataType& data )
{
	*(dataType*)((char*)ptr+offset) = data;
}

int	WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	STARTUPINFO stInfo;
	PROCESS_INFORMATION procInfo;
	HMODULE hKernel32 = GetModuleHandle("Kernel32");
	const char *libPath = GetLibraryPath();

	ZeroMemory(&stInfo, sizeof(stInfo));
	ZeroMemory(&procInfo, sizeof(procInfo));

    wchar_t *envBlockPointers = MakeEnvironment();

	// Create a game process and attach our library to it
    std::string executablePath;

    bool executableSuccess = GetExecutablePath( executablePath );

    if ( !executableSuccess )
    {
        MessageBox( NULL, "Could not find the game executable. Have you properly installed the program?", "Error", MB_OK );
        return EXIT_FAILURE;
    }

	bool success = CreateProcess( executablePath.c_str(), NULL, NULL, NULL, 1, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, (LPVOID)envBlockPointers, NULL, &stInfo, &procInfo ) != FALSE;

	if ( !success )
	{
		MessageBox( NULL, "Failed to create the game process!", "Error", MB_OK );
		return EXIT_FAILURE;
	}

	bool preparationSuccess = true;

    LPVOID remoteDataSection = NULL;
    LPVOID remoteExecutableSection = NULL;

	// Initialize the game using the nastiest stuff ever.
	{
		// Create absolute directory to library
		char pathBuf[1024];
		GetCurrentDirectory( sizeof(pathBuf), pathBuf );

		strcat( pathBuf, libPath );

		size_t pathSize = strlen( pathBuf ) + 1;

		// Get the current directory and prepare it
		const char *curDir = GetExecutableCurrentDirectory();

		size_t curDirSize = strlen( curDir ) + 1;

		// Prepare a data block and an executive block to be patched into the application.
		size_t requiredDataBlockSize = pathSize + curDirSize;

		void *dataBlock = malloc( requiredDataBlockSize );

		// Write the data contents.
		char *remoteCurDirPtr = (char*)dataBlock;
		char *remoteLibPathPtr = remoteCurDirPtr + curDirSize;

		// Write the stuff.
		memcpy( remoteCurDirPtr, curDir, curDirSize );
		memcpy( remoteLibPathPtr, pathBuf, pathSize );

		size_t remoteCurDirOffset = 0;
		size_t remoteLibPathOffset = remoteCurDirOffset + curDirSize;

		// Push the data block to the application.
		remoteDataSection = VirtualAllocEx( procInfo.hProcess, NULL, requiredDataBlockSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

		SIZE_T actuallyDataWritten = 0;

		BOOL writeDataSuccess = WriteProcessMemory( procInfo.hProcess, remoteDataSection, dataBlock, requiredDataBlockSize, &actuallyDataWritten );

		DWORD oldProtect;
		VirtualProtectEx( procInfo.hProcess, remoteDataSection, requiredDataBlockSize, PAGE_READONLY, &oldProtect );

		// We can free our local copy of the data block.
		free( dataBlock );

		// Now create the executable remote data.
		void *codeBlock = NULL;
		size_t codeBlockSize = 0;

		GetApplicationInitializationShellCode( codeBlock, codeBlockSize );

		// We need to grab a local copy of the executive data, so we can modify it.
		void *codeBlockCopy = malloc( codeBlockSize );

		memcpy( codeBlockCopy, codeBlock, codeBlockSize );

		// Modify it so it has pointers to remote data.
		size_t instrOffset = 7;

		MemPutOffset( codeBlockCopy, instrOffset, (DWORD)GetProcAddress( hKernel32, "SetCurrentDirectoryA" ) );
		instrOffset += 5;
		MemPutOffset( codeBlockCopy, instrOffset, (DWORD)remoteDataSection + remoteCurDirOffset );
		instrOffset += 8;
#ifdef _DEBUG
		MemPutOffset( codeBlockCopy, instrOffset, (DWORD)GetProcAddress( hKernel32, "IsDebuggerPresent" ) );
		instrOffset += 11;
#endif
		MemPutOffset( codeBlockCopy, instrOffset, (DWORD)GetProcAddress( hKernel32, "LoadLibraryA" ) );
		instrOffset += 5;
		MemPutOffset( codeBlockCopy, instrOffset, (DWORD)remoteDataSection + remoteLibPathOffset );
		instrOffset += 8;

		// Patch the application entry point.
		CONTEXT remoteContext;
		remoteContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

		GetThreadContext( procInfo.hThread, &remoteContext );

		// Write the old entry point into our remote shell-code.
		MemPutOffset( codeBlockCopy, 1, remoteContext.Eax );

		// Commit the executable region to the application.
		remoteExecutableSection = VirtualAllocEx( procInfo.hProcess, NULL, codeBlockSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

		SIZE_T actuallyExecutiveWritten = 0;

		BOOL executeWriteSuccess = WriteProcessMemory( procInfo.hProcess, remoteExecutableSection, codeBlockCopy, codeBlockSize, &actuallyExecutiveWritten );

        // Make the executable region read-only.
        VirtualProtect( remoteExecutableSection, codeBlockSize, PAGE_EXECUTE, &oldProtect );

		// We can free the local copy of our executive block.
		free( codeBlockCopy );

		// The EAX register at process creation time is the process entry point.
		// Changing it actually changes the offial entry point.
		remoteContext.Eax = (DWORD)remoteExecutableSection;

		// Change the process entry point.
		BOOL contextSetSuccess = SetThreadContext( procInfo.hThread, &remoteContext );

		// We suceeded.
		preparationSuccess = true;
	}

	if ( preparationSuccess )
	{
		// Resume execution
  		ResumeThread( procInfo.hThread );

		// We need to wait until the process has terminated, since we simulate the original spel.dat!
		WaitForSingleObject( procInfo.hThread, INFINITE );
	}
	else
	{
		// Terminate everything.
		TerminateProcess( procInfo.hProcess, 0x80000001 );
	}

	// Clean up stuff.
    if ( remoteExecutableSection != NULL )
    {
        VirtualFreeEx( procInfo.hProcess, remoteExecutableSection, 0, MEM_RELEASE );
        VirtualFreeEx( procInfo.hProcess, remoteDataSection, 0, MEM_RELEASE );
    }

	CloseHandle( procInfo.hProcess );
	CloseHandle( procInfo.hThread );

	return EXIT_SUCCESS;
}