#pragma once

namespace barto_gdbserver {
	bool init();
	void close();
	void vsync();
	bool debug();
}