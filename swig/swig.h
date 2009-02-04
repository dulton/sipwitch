// Copyright (C) 2009 David Sugar, Tycho Softworks.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Transitional object for call information

struct Calls {
	char source[96];
	char target[96];
	unsigned long started, active;
	unsigned long sequence;
	int cid;
};

// Transitional object for primary server statistics

struct Stats {
    char id[16];

	struct {
		unsigned long total;
		unsigned short current, peak;
	} data[2];

	unsigned long lastcall;
	unsigned short members;
};

// Transitional object for prior server statistics

struct PStats {
	char id[16];

	struct {
		unsigned long total;
		unsigned short min, max;
	} period[2];

	unsigned long lastcall;
	unsigned short members;
};




