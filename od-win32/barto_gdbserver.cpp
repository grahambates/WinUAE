#include "sysconfig.h"
#include <Ws2tcpip.h>
#include "sysdeps.h"

#include <thread>

#include "options.h"
#include "memory.h"
#include "newcpu.h"
#include "debug.h"
#include "inputdevice.h"
#include "uae.h"
#include "debugmem.h"

// from main.cpp
extern struct uae_prefs currprefs;

// from debug.cpp
extern uae_u8 *get_real_address_debug(uaecptr addr);
#define TRACE_SKIP_INS 1
#define TRACE_MATCH_PC 2
#define TRACE_MATCH_INS 3
#define TRACE_RANGE_PC 4
#define TRACE_SKIP_LINE 5
#define TRACE_RAM_PC 6
#define TRACE_NRANGE_PC 7
#define TRACE_CHECKONLY 10
/*static*/ extern int trace_mode;
/*static*/ extern uae_u32 trace_param1;
/*static*/ extern uae_u32 trace_param2;
/*static*/ extern uaecptr processptr;
/*static*/ extern uae_char *processname;

#include "barto_gdbserver.h"

// -s use_gui=no -s quickstart=a500 -s filesystem=rw,dh0:c:\cygwin64\home\Chuck\amiga_test

// /opt/amiga/8.2.0/bin/m68k-amiga-elf-gdb -ex 'set debug remote 1' -ex 'target remote :2345' test.elf
// /opt/amiga/8.2.0/bin/m68k-amiga-elf-gdb -ex 'set debug remote 1' -ex 'set remotetimeout 100' -ex 'target remote :2345' test.elf
// /opt/amiga/8.2.0/bin/m68k-amiga-elf-gdb -ex 'set debug remote 1' -ex 'set remotetimeout 100' -ex 'target extended-remote :2345' test.elf
// https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html
// Visual Studio command window: Debug.MIDebugLog /on:c:\amiga\log

namespace barto_gdbserver {
	bool is_connected();
	bool data_available();
	void disconnect();

	static constexpr char hex[]{ "0123456789abcdef" };
	static std::string hex8(uint8_t v) {
		std::string ret;
		ret += hex[v >> 4];
		ret += hex[v & 0xf];
		return ret;
	}
	static std::string hex32(uint32_t v) {
		std::string ret;
		for(int i = 28; i >= 0; i -= 4)
			ret += hex[(v >> i) & 0xf];
		return ret;
	}

	std::thread connect_thread;
	PADDRINFOW socketinfo;
	SOCKET gdbsocket{ INVALID_SOCKET };
	SOCKET gdbconn{ INVALID_SOCKET };
	char socketaddr[sizeof SOCKADDR_INET];
	bool useAck{ true };
	uint32_t baseText{}, baseData{}, baseBss{};

	enum class state {
		inited,
		connected,
		debugging,
	};

	state debugger_state{ state::inited };

	bool is_connected() {
		socklen_t sa_len = sizeof SOCKADDR_INET;
		if(gdbsocket == INVALID_SOCKET)
			return false;
		if(gdbconn == INVALID_SOCKET) {
			struct timeval tv;
			fd_set fd;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			fd.fd_array[0] = gdbsocket;
			fd.fd_count = 1;
			if(select(1, &fd, nullptr, nullptr, &tv)) {
				gdbconn = accept(gdbsocket, (struct sockaddr*)socketaddr, &sa_len);
				if(gdbconn != INVALID_SOCKET)
					write_log("GDBSERVER: connection accepted\n");
			}
		}
		return gdbconn != INVALID_SOCKET;
	}

	bool data_available() {
		if(is_connected()) {
			struct timeval tv;
			fd_set fd;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			fd.fd_array[0] = gdbconn;
			fd.fd_count = 1;
			int err = select(1, &fd, nullptr, nullptr, &tv);
			if(err == SOCKET_ERROR) {
				disconnect();
				return false;
			}
			if(err > 0)
				return true;
		}
		return false;
	}

	bool listen() {
		write_log("GDBSERVER: listen()\n");

		assert(debugger_state == state::inited);

		WSADATA wsaData = { 0 };
		if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			DWORD lasterror = WSAGetLastError();
			write_log(_T("GDBSERVER: can't open winsock, error %d\n"), lasterror);
			return false;
		}
		int err;
		const int one = 1;
		const struct linger linger_1s = { 1, 1 };
		constexpr auto name = _T("127.0.0.1");
		constexpr auto port = _T("2345");

		err = GetAddrInfoW(name, port, nullptr, &socketinfo);
		if(err < 0) {
			write_log(_T("GDBSERVER: GetAddrInfoW() failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}
		gdbsocket = socket(socketinfo->ai_family, socketinfo->ai_socktype, socketinfo->ai_protocol);
		if(gdbsocket == INVALID_SOCKET) {
			write_log(_T("GDBSERVER: socket() failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}
		err = ::bind(gdbsocket, socketinfo->ai_addr, socketinfo->ai_addrlen);
		if(err < 0) {
			write_log(_T("GDBSERVER: bind() failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}
		err = ::listen(gdbsocket, 1);
		if(err < 0) {
			write_log(_T("GDBSERVER: listen() failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}
		err = setsockopt(gdbsocket, SOL_SOCKET, SO_LINGER, (char*)&linger_1s, sizeof linger_1s);
		if(err < 0) {
			write_log(_T("GDBSERVER: setsockopt(SO_LINGER) failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}
		err = setsockopt(gdbsocket, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof one);
		if(err < 0) {
			write_log(_T("GDBSERVER: setsockopt(SO_REUSEADDR) failed, %s:%s: %d\n"), name, port, WSAGetLastError());
			return false;
		}

		return true;
	}

	bool init() {
		if(currprefs.debugging_features & (1 << 2)) { // "gdbserver"
			warpmode(1);

			// disable console
			static TCHAR empty[2] = { 0 };
			setconsolemode(empty, 1);

			activate_debugger();
			// from debug.cpp@process_breakpoint()
			processptr = 0;
			xfree(processname);
			processname = nullptr;
			constexpr TCHAR name[]{ _T("runme.exe") };
			processname = ua(name);
			trace_mode = TRACE_CHECKONLY;

			// call as early as possible to avoid delays with GDB having to retry to connect...
			listen();
		}

		return true;
	}

	void close() {
		if(gdbconn != INVALID_SOCKET)
			closesocket(gdbconn);
		gdbconn = INVALID_SOCKET;
		if(gdbsocket != INVALID_SOCKET)
			closesocket(gdbsocket);
		gdbsocket = INVALID_SOCKET;
		if(socketinfo)
			FreeAddrInfoW(socketinfo);
		socketinfo = nullptr;
		WSACleanup();
	}

	void disconnect() {
		if(gdbconn == INVALID_SOCKET)
			return;
		closesocket(gdbconn);
		gdbconn = INVALID_SOCKET;
		write_log(_T("GDBSERVER: disconnect\n"));
	}

	static std::string get_registers() {
		enum regnames {
			D0, D1, D2, D3, D4, D5, D6, D7,
			A0, A1, A2, A3, A4, A5, A6, A7,
			SR, PC
		};

		//debugmem_list_stackframe_test(false); // TEST

		// need to byteswap because GDB expects 68k big-endian
		uint32_t registers[18];
		registers[SR] = _byteswap_ulong(regs.sr);
		registers[PC] = _byteswap_ulong(M68K_GETPC);
		for(int i = 0; i < 8; i++) {
			registers[D0 + i] = _byteswap_ulong(m68k_dreg(regs, i));
			registers[A0 + i] = _byteswap_ulong(m68k_areg(regs, i));
		}
		write_log("GDBSERVER: PC=%x\n", M68K_GETPC);

		auto mem2hex = [](const void* data, size_t length) -> std::string {
			std::string ret;
			for(auto u8data = reinterpret_cast<const uint8_t*>(data); length; length--, u8data++) {
				ret += hex[*u8data >> 4];
				ret += hex[*u8data & 0xf];
			}
			return ret;
		};
		return mem2hex(registers, sizeof(registers));
	}

	void print_breakpoints() {
		write_log("GDBSERVER: Breakpoints:\n");
		for(auto& bpn : bpnodes) {
			if(bpn.enabled) {
				write_log("GDBSERVER: - %d, 0x%x, 0x%x\n", bpn.type, bpn.value1, bpn.value2);
			}
		}
	}

	void send_ack(const std::string& ack) {
		if(useAck && !ack.empty()) {
			write_log("GDBSERVER: <- %s\n", ack.c_str());
			int result = send(gdbconn, ack.data(), ack.length(), 0);
			if(result == SOCKET_ERROR)
				write_log(_T("GDBSERVER: error sending ack: %d\n"), WSAGetLastError());
		}
	}

	void send_response(std::string response) {
		if(!response.empty()) {
			write_log("GDBSERVER: <- %s\n", response.substr(1).c_str());
			uint8_t cksum{};
			for(size_t i = 1; i < response.length(); i++)
				cksum += response[i];
			response += '#';
			response += hex[cksum >> 4];
			response += hex[cksum & 0xf];
			int result = send(gdbconn, response.data(), response.length(), 0);
			if(result == SOCKET_ERROR)
				write_log(_T("GDBSERVER: error sending data: %d\n"), WSAGetLastError());
		}
	}

	void handle_packet() {
		if(data_available()) {
			char buf[512];
			auto result = recv(gdbconn, buf, sizeof(buf) - 1, 0);
			if(result > 0) {
				buf[result] = '\0';
				write_log("GDBSERVER: received %d bytes: >>%s<<\n", result, buf);
				std::string request{ buf }, ack{}, response;
				if(request[0] == '+') {
					request = request.substr(1);
				} else if(request[0] == '-') {
					write_log("GDBSERVER: client non-ack'd our last packet\n");
					request = request.substr(1);
				}
				if(!request.empty() && request[0] == 0x03) {
					// Ctrl+C
					ack = "+";
					response = "$";
					response += "S05"; // SIGTRAP
					debugger_state = state::debugging;
					activate_debugger();
				} else if(!request.empty() && request[0] == '$') {
					ack = "-";
					auto end = request.find('#');
					if(end != std::string::npos) {
						uint8_t cksum{};
						for(size_t i = 1; i < end; i++)
							cksum += request[i];
						if(request.length() >= end + 2) {
							if(tolower(request[end + 1]) == hex[cksum >> 4] && tolower(request[end + 2]) == hex[cksum & 0xf]) {
								request = request.substr(1, end - 1);
								write_log("GDBSERVER: -> %s\n", request.c_str());
								ack = "+";
								response = "$";
								if(request.substr(0, strlen("qSupported")) == "qSupported") {
									response += "PacketSize=512;BreakpointCommands+;swbreak+;hwbreak+;QStartNoAckMode+;vContSupported+;";
								} else if(request.substr(0, strlen("qAttached")) == "qAttached") {
									response += "1";
								} else if(request.substr(0, strlen("qTStatus")) == "qTStatus") {
									response += "T0";
								} else if(request.substr(0, strlen("QStartNoAckMode")) == "QStartNoAckMode") {
									send_ack(ack);
									useAck = false;
									response += "OK";
								} else if(request.substr(0, strlen("qfThreadInfo")) == "qfThreadInfo") {
									response += "m1";
								} else if(request.substr(0, strlen("qsThreadInfo")) == "qsThreadInfo") {
									response += "l";
								} else if(request.substr(0, strlen("qC")) == "qC") {
									response += "QC1";
								} else if(request.substr(0, strlen("qOffsets")) == "qOffsets") {
									auto BADDR = [](auto bptr) { return bptr << 2; };
									auto BSTR = [](auto bstr) { return std::string(reinterpret_cast<char*>(bstr) + 1, bstr[0]); };
									// from debug.cpp@show_exec_tasks
									auto execbase = get_long_debug(4);
									auto ThisTask = get_long_debug(execbase + 276);

									auto ln_Name = reinterpret_cast<char*>(get_real_address_debug(get_long_debug(ThisTask + 10)));
									write_log("GDBSERVER: ln_Name = %s\n", ln_Name);
									auto ln_Type = get_byte_debug(ThisTask + 8);
									bool process = ln_Type == 13; // NT_PROCESS
									if(process) {
										auto pr_SegList = BADDR(get_long_debug(ThisTask + 128));
										auto numSegLists = get_long_debug(pr_SegList + 0);
										auto segList = BADDR(get_long_debug(pr_SegList + 12)); // from debug.cpp@debug()
										auto pr_CLI = BADDR(get_long_debug(ThisTask + 172));
										int pr_TaskNum = get_long_debug(ThisTask + 140);
										if(pr_CLI && pr_TaskNum) {
											auto cli_CommandName = BSTR(get_real_address_debug(BADDR(get_long_debug(pr_CLI + 16))));
											write_log("GDBSERVER: cli_CommandName = %s\n", cli_CommandName.c_str());
											segList = BADDR(get_long_debug(pr_CLI + 60));
										}
										baseText = baseData = baseBss = 0;
										for(int i = 0; segList; i++) {
											auto size = get_long_debug(segList - 4) - 4;
											auto base = segList + 4;
											switch(i) {
											case 0: baseText = base; break;
											case 1: baseData = base; break;
											case 2: baseBss = base; break;
											}
											write_log("GDBSERVER:   base=%x; size=%x\n", base, size);
											segList = BADDR(get_long_debug(segList));
										}
										response += "Text=" + hex32(baseText) + ";Data=" + hex32(baseData) + ";Bss=" + hex32(baseBss);
										// test.hunk: elf2hunk says #0 HUNK_CODE: 0x158 bytes; segList says 0x15c bytes
										//                          #1 HUNK_DATA: 0x050 bytes; segList says 0x054 bytes
										//                          #2 HUNK_BSS:  0x044 bytes; segList says 0x048 bytes
									}
								} else if(request.substr(0, strlen("vCont?")) == "vCont?") {
									response += "vCont;c;C;s;S;t;r";
								} else if(request.substr(0, strlen("vCont;")) == "vCont;") {
									auto actions = request.substr(strlen("vCont;"));
									while(!actions.empty()) {
										std::string action;
										// split actions by ';'
										auto semi = actions.find(';');
										if(semi != std::string::npos) {
											action = actions.substr(0, semi);
											actions = actions.substr(semi + 1);
										} else {
											action = actions;
											actions.clear();
										}
										// thread specified by ':'
										auto colon = action.find(':');
										if(colon != std::string::npos) {
											// ignore thread ID
											action = action.substr(0, colon);
										}

										// hmm.. what to do with multiple actions?!

										if(action == "s") { // single-step
											trace_param1 = 1;
											trace_mode = TRACE_SKIP_INS;
											exception_debugging = 1;
											debugger_state = state::connected;
											send_ack(ack);
											return;
										} else if(action == "c") { // continue
											debugger_state = state::connected;
											deactivate_debugger();
											send_ack(ack);
											return;
										} else if(action[0] == 'r') { // keep stepping in range
											auto comma = action.find(',', 3);
											if(comma != std::string::npos) {
												uaecptr start = strtoul(action.data() + 1, nullptr, 16);
												uaecptr end = strtoul(action.data() + comma + 1, nullptr, 16);
												trace_mode = TRACE_NRANGE_PC;
												trace_param1 = start;
												trace_param2 = end;
												debugger_state = state::connected;
												send_ack(ack);
												return;
											}
										} else {
											write_log("GDBSERVER: unknown vCont action: %s\n", action.c_str());
										}
									}
								} else if(request[0] == 'H') {
									response += "OK";
								} else if(request[0] == 'T') {
									response += "OK";
/*								} else if(request.substr(0, strlen("vRun")) == "vRun") {
									debugger_state = state::wait_for_process;
									activate_debugger();
									send_ack(ack);
									return;
*/								} else if(request[0] == 'D') { // detach
									response += "OK";
/*								} else if(request[0] == '!') { // enable extended mode
									response += "OK";
*/								} else if(request[0] == '?') { // reason for stopping
									response += "S05"; // SIGTRAP
								} else if(request[0] == 's') { // single-step
									assert(!"should have used vCont;s");
								} else if(request[0] == 'c') { // continue
									assert(!"should have used vCont;c");
								} else if(request[0] == 'k') { // kill
									uae_quit();
									deactivate_debugger();
									return;
								} else if(request.substr(0, 2) == "Z0") { // set software breakpoint
									auto comma = request.find(',', strlen("Z0"));
									if(comma != std::string::npos) {
										uaecptr adr = strtoul(request.data() + strlen("Z0,"), nullptr, 16);
										if(adr == 0xffffffff) {
											// step out of kickstart
											trace_mode = TRACE_RANGE_PC;
											trace_param1 = 0;
											trace_param2 = 0xF80000;
											response += "OK";
										} else if(adr == 0xeeeeeeee) {
											// step out of interrupt (until RTE)
											trace_mode = TRACE_MATCH_INS;
											trace_param1 = 0x4e73; // rte
											response += "OK";
										} else {
											for(auto& bpn : bpnodes) {
												if(bpn.enabled)
													continue;
												bpn.value1 = adr;
												bpn.type = BREAKPOINT_REG_PC;
												bpn.oper = BREAKPOINT_CMP_EQUAL;
												bpn.enabled = 1;
												trace_mode = 0;
												print_breakpoints();
												response += "OK";
												break;
											}
											// TODO: error when too many breakpoints!
										}
									} else
										response += "E01";
								} else if(request.substr(0, 2) == "z0") { // clear software breakpoint
									auto comma = request.find(',', strlen("z0"));
									if(comma != std::string::npos) {
										uaecptr adr = strtoul(request.data() + strlen("z0,"), nullptr, 16);
										if(adr == 0xffffffff) {
											response += "OK";
										} else {
											for(auto& bpn : bpnodes) {
												if(bpn.enabled && bpn.value1 == adr) {
													bpn.enabled = 0;
													trace_mode = 0;
													print_breakpoints();
													response += "OK";
													break;
												}
											}
											// TODO: error when breakpoint not found
										}
									} else
										response += "E01";
								} else if(request[0] == 'g') { // get registers
									response += get_registers();
								} else if(request[0] == 'm') { // read memory
									auto comma = request.find(',');
									if(comma != std::string::npos) {
										std::string mem;
										uaecptr adr = strtoul(request.data() + strlen("m"), nullptr, 16);
										int len = strtoul(request.data() + comma + 1, nullptr, 16);
										write_log("GDBSERVER: want 0x%x bytes at 0x%x\n", len, adr);
										while(len-- > 0) {
											auto data = debug_read_memory_8(adr);
											if(data == -1) {
												write_log("GDBSERVER: error reading memory at 0x%x\n", len, adr);
												response += "E01";
												mem.clear();
												break;
											}
											data &= 0xff; // custom_bget seems to have a problem?
											mem += hex[data >> 4];
											mem += hex[data & 0xf];
											adr++;
										}
										response += mem;
									} else
										response += "E01";
								}
							} else
								write_log("GDBSERVER: packet checksum mismatch: got %c%c, want %c%c\n", tolower(request[end + 1]), tolower(request[end + 2]), hex[cksum >> 4], hex[cksum & 0xf]);
						} else
							write_log("GDBSERVER: packet checksum missing\n");
					} else
						write_log("GDBSERVER: packet end marker '#' not found\n");
				}

				send_ack(ack);
				send_response(response);
			} else if(result == 0) {
				disconnect();
			} else {
				write_log(_T("GDBSERVER: error receiving data: %d\n"), WSAGetLastError());
				disconnect();
			}
		}
		if(!is_connected()) {
			debugger_state = state::inited;
			close();
			deactivate_debugger();
		}
	}

	void vsync() {
		if(!(currprefs.debugging_features & (1 << 2))) // "gdbserver"
			return;

		if(debugger_state == state::connected && data_available()) {
			handle_packet();
		}
	}

	uaecptr KPutCharX{};

	// returns true if gdbserver handles debugging
	bool debug() {
		if(!(currprefs.debugging_features & (1 << 2))) // "gdbserver"
			return false;

		// break at start of process
		if(debugger_state == state::inited) {
			//KPutCharX
			auto execbase = get_long_debug(4);
			KPutCharX = execbase - 0x204;
			for (auto& bpn : bpnodes) {
				if (bpn.enabled)
					continue;
				bpn.value1 = KPutCharX;
				bpn.type = BREAKPOINT_REG_PC;
				bpn.oper = BREAKPOINT_CMP_EQUAL;
				bpn.enabled = 1;
				write_log("GDBSERVER: Breakpoint for KPutCharX at 0x%x installed\n", KPutCharX);
				break;
			}

			warpmode(0);
			// from debug.cpp@process_breakpoint()
			processptr = 0;
			xfree(processname);
			processname = nullptr;
			write_log("GDBSERVER: Waiting for connection...\n");
			while(!is_connected()) {
				write_log(".");
				Sleep(100);
			}
			write_log("\n");
			useAck = true;
			debugger_state = state::debugging;
			debugmem_enable_stackframe(true);
			debugmem_trace = true;
		}

		// something stopped execution and entered debugger
		if(debugger_state == state::connected) {
			auto pc = munge24(m68k_getpc());
			if (pc == KPutCharX) {
				auto ascii = static_cast<uint8_t>(m68k_dreg(regs, 0));
				send_response("$O" + hex8(ascii));
				deactivate_debugger();
				return true;
			}

			std::string response{"S05"};
			for(const auto& bpn : bpnodes) {
				if(bpn.enabled && bpn.type == BREAKPOINT_REG_PC && bpn.value1 == pc) {
					response = "T05swbreak:;";
					break;
				}
			}
			send_response("$" + response);
			trace_mode = 0;
			debugger_state = state::debugging;
		}

		// debugger active
		while(debugger_state == state::debugging) {
			handle_packet();

			MSG msg{};
			while(PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			Sleep(1);
		}

		return true;
	}
} // namespace barto_gdbserver