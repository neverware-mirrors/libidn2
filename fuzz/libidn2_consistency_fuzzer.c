/*
 * Copyright(c) 2018 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libidn.
 */

#include <config.h>

#undef NDEBUG
#include <assert.h> /* assert */
#include <stdio.h> /* assert */
#include <stdint.h> /* uint8_t, uint32_t */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */
#include <strings.h> /* strcasecmp */

#include "idn2.h"
#include "fuzzer.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *domain;
	uint32_t *out;

	if (size > 1024)
		return 0;

	domain = (char *) malloc(size + 4 + 1);
	assert(domain != NULL);

	// 0 terminate
	memcpy(domain, "xn--", 4);
	memcpy(domain + 4, data, size);
	domain[size + 4] = 0;

	for (char *p = domain + 4; *p; p++)
		if (*p == '.') *p='a';

	// internally calls idn2_to_unicode_8zlz(), idn2_to_unicode_8z8z(), idn2_to_unicode_8z4z()
	if (idn2_to_unicode_8z4z(domain, &out, 0) == IDN2_OK) {
		uint32_t *p;
		char *domain2 = NULL;
		int rc;

	fprintf(stderr, "###IN %s ", domain);
	for (const char *p = domain + 4; *p; p++) fprintf(stderr, "%02x ", (unsigned) *p);
	fprintf(stderr, "\n");

		// don't allow invalid unicode values (D800..DBFF are UTF-16 surrogates)
		for (p = out; *p; p++) {
			if (!(*p > 0 && *p <= 0x10FFFF && (*p < 0xD800 || *p > 0xDBFF)))
				fprintf(stderr, "Invalid unicode value: %08X from %s\n", *p, domain);
			assert(*p > 0 && *p <= 0x10FFFF && (*p < 0xD800 || *p > 0xDBFF));
		}

		if ((rc = idn2_to_ascii_4z(out, &domain2, 0)) != IDN2_OK) {
			for (p = out; *p; p++) {
				fprintf(stderr, "%08x ", *p);
			}
			fprintf(stderr, "\n");
			fprintf(stderr, "toASCII failed: %s rc=%d\n", domain, rc);

//			if (rc != IDN2_LEADING_COMBINING && rc != IDN2_DISALLOWED && rc != IDN2_HYPHEN_STARTEND && rc != IDN2_PUNYCODE_BIG_OUTPUT
//				&& rc != IDN2_TOO_BIG_LABEL && rc != IDN2_2HYPHEN)
//				abort();
		}

		if (rc == IDN2_OK) {
			if (strcasecmp(domain, domain2) == 0)
				fprintf(stderr, "###OK '%s' - '%s'\n", domain, domain2);
			else
				fprintf(stderr, "###ERR '%s' - '%s'\n", domain, domain2);

//			assert(strcasecmp(domain + 4, domain2) == 0);
		}

		idn2_free(domain2);
		idn2_free(out);
	}

	free(domain);
	return 0;
}
