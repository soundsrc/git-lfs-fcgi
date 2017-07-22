/*
 * Copyright (c) 2017 Sound <sound@sagaforce.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "oid_utils.h"
#include <string.h>

static unsigned char hex_to_int(char hex)
{
	if(hex >= 'a' && hex <= 'f') {
		return 10 + hex - 'a';
	} else if(hex >= 'A' && hex <= 'F') {
		return 10 + hex - 'A';
	} else if(hex >= '0' && hex <= '9') {
		return hex - '0';
	}
	return 0;
}

static unsigned char int_to_hex(int nibble)
{
	if(nibble < 0 || nibble > 15) return 0;
	if(nibble < 10) return '0' + nibble;
	return 'a' + (nibble - 10);
}

int oid_is_valid(const char *oid)
{
	if(strnlen(oid, 65) != 64) return 0;
	
	for(int i = 0; i < 64; i++) {
		if(!((oid[i] >= '0' && oid[i] <= '9') ||
			 (oid[i] >='a' && oid[i] <= 'f')))
		{
			return 0;
		}
	}
	
	return 1;
}

void oid_to_string(unsigned char oid[32], char str[65])
{
	for(int i = 0; i < 32; ++i) {
		str[i << 1] = int_to_hex(oid[i] >> 4);
		str[(i << 1) + 1] = int_to_hex(oid[i] & 0xF);
	}
	str[64] = 0;
}

int oid_from_string(const char str[65], unsigned char oid[32])
{
	if(!oid_is_valid(str)) return -1;
	
	for(int i = 0; i < 32; i++) {
		oid[i] = (hex_to_int(oid[i << 1]) << 4) | hex_to_int(oid[(i << 1) + 1]);
	}
	
	return 0;
}
