#include <ctime>
#include <iostream>
#include <MinHook.h>
#include <string>
#include <TlHelp32.h>
#include <Windows.h>
#include <WinInet.h>
#include <fmt/format.h>
#pragma comment( lib, "Wininet" )

void *original_write_process_memory = nullptr, *original_httpopenrequest, *original_internet_connecta, *original_ntwrite_process_memory, *original_httpsendrequest, *original_recv_hook, *original_send_hook, *original_internet_read_file, *original_internet_connectw, *original_open_requestw, *original_open_requesta, *original_loadlibrary, *original_openprocess, *original_winhttpconnect, *original_winhttpreaddata = nullptr;

int __stdcall write_process_memory( const HANDLE process, const LPVOID base_address, const LPCVOID buffer, const SIZE_T size, const DWORD number_of_bytes_written ) {
	auto* handle = HANDLE( );
	static auto rewrite = false;

	const auto process_pid = GetProcessId( process );
	fmt::print( "[WriteProcessMemory] pid: {} \n", process_pid );

	rewrite = true;
	if ( rewrite )
		handle = CreateFileA( std::string( std::to_string( rand( ) % 500 ).append( "-wpm.dll" ) ).c_str( ), FILE_FLAG_OVERLAPPED, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr );

	WriteFile( handle, buffer, number_of_bytes_written, nullptr, nullptr );

	rewrite = false;

	return static_cast<int( __thiscall*)( HANDLE, LPVOID, LPCVOID, SIZE_T, DWORD )>( original_write_process_memory )( process, base_address, buffer, size, number_of_bytes_written );
}

LONG __stdcall nt_write_process_memory( const HANDLE process, const PVOID base_address, const PVOID buffer, const ULONG number_of_bytes_to_write, const DWORD unk ) {
	auto* handle = HANDLE( );
	static auto rewrite = false;

	const auto process_pid = GetProcessId( process );
	fmt::print( "[NtWriteProcessMemory] pid: {} \n", process_pid );

	rewrite = true;
	if ( rewrite )
		handle = CreateFileA( std::string( std::to_string( rand( ) % 500 ) ).append( "-ntwpm.dll" ).c_str( ), FILE_FLAG_OVERLAPPED, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr );

	WriteFile( handle, buffer, number_of_bytes_to_write, nullptr, nullptr );

	rewrite = false;

	return static_cast<int( __thiscall*)( HANDLE, LPVOID, LPCVOID, SIZE_T, DWORD )>( original_ntwrite_process_memory )( process, base_address, buffer, number_of_bytes_to_write, unk );
}

int __stdcall recv_hook( const SOCKET s, char* buffer, const int length, const int flags ) {
	if ( buffer && !std::string( buffer ).empty( ) )
		fmt::print( "[recv] buffer: {}, length: {} \n", buffer, length );

	return static_cast<int( __thiscall*)( SOCKET, char*, int, int )>( original_recv_hook )( s, buffer, length, flags );
}

int __stdcall send_hook( const SOCKET s, char* buffer, const int length, const int flags ) {
	if ( buffer && !std::string( buffer ).empty( ) )
		fmt::print( "[send] buffer: {}, length: {} \n", buffer, length );

	return static_cast<int( __thiscall*)( SOCKET, char*, int, int )>( original_send_hook )( s, buffer, length, flags );
}

bool internet_read_file( void* file, const LPVOID buffer, const DWORD number_of_bytes_to_read, const LPDWORD number_of_bytesread ) {
	if ( buffer )
		fmt::print( "[InternetReadFile] buffer: {} \n", buffer );

	return static_cast<bool( __thiscall*)( void*, LPVOID, DWORD, LPDWORD )>( original_internet_read_file )( file, buffer, number_of_bytes_to_read, number_of_bytesread );
}

HINTERNET internet_connectw( const HINTERNET handle, const LPCWSTR server_name, const INTERNET_PORT server_port, const LPCWSTR name, const LPCWSTR password, const DWORD service, const DWORD flags, DWORD* context ) {
	printf( "[InternetConnectW] address: %ls, port: %s \n", server_name, std::to_string( server_port ).c_str( ) );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD* )>( original_internet_connectw )( handle, server_name, server_port, name, password, service, flags, context );
}

HINTERNET open_requestw( const HINTERNET handle, const LPCWSTR verb, const LPCWSTR object_name, const LPCWSTR version, const LPCWSTR referrer, LPCWSTR* accepted_types, const DWORD flags, DWORD* context ) {
	printf( "[HttpOpenRequestW] verb: %ls, name: %ls \n", verb, object_name );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD* )>( original_open_requestw )( handle, verb, object_name, version, referrer, accepted_types, flags, context );
}

HINTERNET internet_connecta( const HINTERNET handle, const LPCSTR server_name, const INTERNET_PORT server_port, const LPCSTR name, const LPCSTR password, const DWORD service, const DWORD flags, DWORD* context ) {
	printf( "[InternetConnectA] address: %s, port: %s \n", server_name, std::to_string( server_port ).c_str( ) );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD* )>( original_internet_connecta )( handle, server_name, server_port, name, password, service, flags, context );
}

HINTERNET open_requesta( const HINTERNET handle, const LPCSTR verb, const LPCSTR object_name, const LPCSTR version, const LPCSTR referrer, LPCSTR* accepted_types, const DWORD flags, DWORD* context ) {
	fmt::print( "[HttpOpenRequestA] verb: {}, name: {} \n", verb, object_name );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD* )>( original_open_requesta )( handle, verb, object_name, version, referrer, accepted_types, flags, context );
}

HMODULE load_library( const LPCSTR file_name ) {
	fmt::print( "[LoadLibrary] module name: {} \n", file_name );

	return static_cast<HMODULE( __thiscall*)( LPCSTR )>( original_loadlibrary )( file_name );
}

bool httpsend_request( const HINTERNET handle, const LPCWSTR headers, const DWORD unk, const LPVOID unk2, const DWORD unk3, const DWORD unk4, DWORD* unk5 ) {
	fmt::print( "[WinHttpSendRequest] headers: {} \n", fmt::ptr( headers ) );

	return static_cast<bool( __thiscall*)( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD* )>( original_httpsendrequest )( handle, headers, unk, unk2, unk3, unk4, unk5 );
}

HINTERNET httpopen_request( const HINTERNET handle, const LPCWSTR verb, const LPCWSTR object_name, const LPCWSTR version, const LPCWSTR referrer, LPCWSTR* accepted_types, const DWORD flags ) {
	printf( "[WinHttpOpenRequest] verb: %ls, name: %ls \n", verb, object_name );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD )>( original_httpopenrequest )( handle, verb, object_name, version, referrer, accepted_types, flags );
}

bool winhttp_read_data( const HINTERNET handle, const LPVOID buffer, const DWORD unk1, const DWORD unk2 ) {
	fmt::print( "[WinHttpReadData] buffer: {} \n", fmt::ptr( buffer ) );

	return static_cast<bool( __thiscall*)( HINTERNET, LPVOID, DWORD, DWORD )>( original_winhttpreaddata )( handle, buffer, unk1, unk2 );
}

HINTERNET winhttp_connect( const HINTERNET session, const LPCWSTR server_name, const INTERNET_PORT server_port, const DWORD reserved ) {
	printf( "[WinHttpConnect] address: %ls, port: %s \n", server_name, std::to_string( server_port ).c_str( ) );

	return static_cast<HINTERNET( __thiscall*)( HINTERNET, LPCWSTR, INTERNET_PORT, DWORD )>( original_winhttpconnect )( session, server_name, server_port, reserved );
}

HANDLE open_process( const DWORD access, const bool handle, const DWORD process_id ) {
	const auto get_process_name = [ ]( const DWORD pid ) {
		auto process_info = PROCESSENTRY32( );
		process_info.dwSize = sizeof PROCESSENTRY32;

		auto* const process_snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if ( process_snapshot == INVALID_HANDLE_VALUE )
			return;

		while ( Process32Next( process_snapshot, &process_info ) ) {
			if ( pid == process_info.th32ProcessID && pid != GetCurrentProcessId( ) ) {
				fmt::print( "[OpenProcess] name: {}, pid: {} \n", process_info.szExeFile, pid );
				CloseHandle( process_snapshot );
			}
		}

		CloseHandle( process_snapshot );
	};

	get_process_name( process_id );

	return static_cast<HANDLE( __thiscall*)( DWORD, bool, DWORD )>( original_openprocess )( access, handle, process_id );
}

unsigned long __stdcall initialise( ) {
	AllocConsole( );
	FILE* fp;
	freopen_s( &fp, "CONOUT$", "w", stdout );

	const auto modules = { "kernel32.dll", "ntdll.dll", "ws2_32.dll", "Wininet.dll" };
	for ( const auto* module : modules ) {
		if ( !LoadLibraryA( module ) )
			continue;

		fmt::print( "loaded module: {} \n", module );
	}

	if ( const auto code = MH_Initialize( ); code != MH_OK )
		fmt::print( "failed initializing minhook, error: {} \n", MH_StatusToString( code ) );

	const auto create_hook = []( const wchar_t* module, const LPCSTR name, void* detour, void** original ) {
		if ( const auto code = MH_CreateHookApi( module, name, detour, original ); code != MH_OK )
			fmt::print( "failed hooking {}, error: {} \n", name, MH_StatusToString( code ) );
	};

	create_hook( L"kernel32.dll", "WriteProcessMemory", &write_process_memory, &original_write_process_memory );
	create_hook( L"kernel32.dll", "LoadLibraryA", &load_library, &original_loadlibrary );
	create_hook( L"kernel32.dll", "OpenProcess", &open_process, &original_openprocess );
	create_hook( L"ntdll.dll", "NtWriteVirtualMemory", &nt_write_process_memory, &original_ntwrite_process_memory );
	create_hook( L"ws2_32.dll", "recv", &recv_hook, &original_recv_hook );
	create_hook( L"ws2_32.dll", "send", &send_hook, &original_send_hook );
	create_hook( L"wininet.dll", "InternetReadFile", &internet_read_file, &original_internet_read_file );
	create_hook( L"wininet.dll", "InternetConnectW", &internet_connectw, &original_internet_connectw );
	create_hook( L"wininet.dll", "HttpOpenRequestW", &open_requestw, &original_open_requestw );
	create_hook( L"wininet.dll", "InternetConnectA", &internet_connecta, &original_internet_connecta );
	create_hook( L"wininet.dll", "HttpOpenRequestA", &open_requesta, &original_open_requesta );
	create_hook( L"wininet.dll", "WinHttpSendRequest", &httpsend_request, &original_httpsendrequest );
	create_hook( L"Winhttp.dll", "WinHttpOpenRequest", &httpopen_request, &original_httpopenrequest );
	create_hook( L"Winhttp.dll", "WinHttpReadData", &winhttp_read_data, &original_winhttpreaddata );
	create_hook( L"Winhttp.dll", "WinHttpConnect", &winhttp_connect, &original_winhttpconnect );

	if ( const auto code = MH_EnableHook( nullptr ); code != MH_OK )
		fmt::print( "failed enabling hooks, error: {} \n", MH_StatusToString( code ) );

	return 0L;
}

bool __stdcall DllMain( HINSTANCE, const DWORD reason, LPVOID ) {
	if ( reason != DLL_PROCESS_ATTACH )
		return false;

	if ( auto* const handle = CreateThread( nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>( initialise ), nullptr, 0, nullptr ); handle != nullptr )
		CloseHandle( handle );

	return true;
}
