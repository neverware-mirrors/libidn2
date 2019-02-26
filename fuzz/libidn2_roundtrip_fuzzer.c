/*
 * Copyright(c) 2019 Tim Ruehsen
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
 * This file is part of libidn2.
 */

#include <config.h>

#include <assert.h> /* assert */
#include <stdio.h> /* fprintf */
#include <stdlib.h> /* malloc, free */
#include <string.h> /* memcpy */

#include "idn2.h"
#include "fuzzer.h"

static int flags[] = {
	IDN2_NFC_INPUT|IDN2_USE_STD3_ASCII_RULES,
	IDN2_TRANSITIONAL|IDN2_USE_STD3_ASCII_RULES,
	IDN2_NONTRANSITIONAL|IDN2_USE_STD3_ASCII_RULES
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *domain;
	char *encoded, *decoded, *decoded2;

	if (size > 1024)
		return 0;

	domain = (char *) malloc(size + 1);
	assert(domain != NULL);

	/* 0 terminate */
	memcpy(domain, data, size);
	domain[size] = 0;

	for (int it = 0; it < (int)(sizeof(flags)/sizeof(flags[0])); it++) {
		// this first encoding does NFC encoding as well, so it's not revertable
		if (idn2_lookup_u8((uint8_t *)domain, (uint8_t **)&encoded, flags[it]) == IDN2_OK) {
#ifdef TEST_RUN
			fprintf(stderr, "%s -> %s\n", domain, encoded);
#endif
			// if this decoding succeeds, the following encoding should yield the original string
			if (idn2_to_unicode_8z8z(encoded, &decoded, 0) == IDN2_OK) {
#ifdef TEST_RUN
				fprintf(stderr, "%s -> %s\n", encoded, decoded);
#endif
				int rc = idn2_lookup_u8((uint8_t *)decoded, (uint8_t **)&decoded2, flags[it]);
				if (rc != IDN2_OK)
					fprintf(stderr,"rc=%d\n",rc);
				assert(rc == IDN2_OK);
#ifdef TEST_RUN
				fprintf(stderr, "%s -> %s\n", decoded, decoded2);
#endif
				assert(strcmp(encoded, decoded2) == 0);
				idn2_free(decoded2);
				idn2_free(decoded);
			}
			idn2_free(encoded);
		}
	}

	free(domain);
	return 0;
}
