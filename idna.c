/* idna.c - implementation of high-level IDNA processing function
   Copyright (C) 2011 Simon Josefsson

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#include "idn2.h"

#include <stdlib.h> /* getsubopt */
#include <errno.h> /* errno */
#include <langinfo.h> /* nl_langinfo */

#include "bidi.h"
#include "tables.h"
#include "context.h"
#include "punycode.h"

#include "unictype.h" /* UC_CATEGORY_M */
#include "unistr.h" /* u32_cpy_alloc */
#include "uninorm.h" /* u32_normalize */
#include "unistr.h" /* u32_normalize */

#include "idna.h"

static int
process1 (const int what[], uint32_t **label, size_t *llen)
{
  const int *p = what;

  for (;;)
    {
      switch (*p++)
	{
	case CHECK_NFC:
	  {
	    size_t plen;
	    uint32_t *p = u32_normalize (UNINORM_NFC, *label, *llen,
					 NULL, &plen);
	    int ok;
	    if (p == NULL)
	      {
		if (errno == ENOMEM)
		  return IDN2_MALLOC;
		return IDN2_NFC;
	      }
	    ok = *llen == plen && memcmp (*label, p, plen) == 0;
	    free (p);
	    if (!ok)
	      return IDN2_NOT_NFC;
	    break;
	  }

	case CHECK_2HYPHEN:
	  if (*llen >= 4 && (*label)[2] == '-' && (*label)[3] == '-')
	    return IDN2_2HYPHEN;
	  break;

	case CHECK_HYPHEN_STARTEND:
	  if (*llen > 0 && (*label)[0] == '-' || (*label)[*llen - 1] == '-')
	    return IDN2_HYPHEN_STARTEND;
	  break;

	case CHECK_LEADING_COMBINING:
	  if (*llen > 0 && uc_is_general_category ((*label)[0], UC_CATEGORY_M))
	    return IDN2_LEADING_COMBINING;
	  break;

	case CHECK_DISALLOWED:
	  {
	    size_t i;
	    for (i = 0; i < *llen; i++)
	      if (_idn2_disallowed_p ((*label)[i]))
		return IDN2_DISALLOWED;
	  }
	  break;

	case CHECK_CONTEXTJ:
	  {
	    size_t i;
	    for (i = 0; i < *llen; i++)
	      if (_idn2_contextj_p ((*label)[i]))
		return IDN2_CONTEXTJ;
	  }
	  break;

	case CHECK_CONTEXTJ_RULE:
	  {
	    size_t i;
	    int rc;

	    for (i = 0; i < *llen; i++)
	      {
		rc = _idn2_contextj_rule (*label, *llen, i);
		if (rc != IDN2_OK)
		  return rc;
	      }
	  }
	  break;

	case CHECK_CONTEXTO:
	  {
	    size_t i;
	    for (i = 0; i < *llen; i++)
	      if (_idn2_contexto_p ((*label)[i]))
		return IDN2_CONTEXTO;
	  }
	  break;

	case CHECK_CONTEXTO_WITH_RULE:
	  {
	    size_t i;
	    for (i = 0; i < *llen; i++)
	      if (_idn2_contexto_p ((*label)[i])
		  && !_idn2_contexto_with_rule ((*label)[i]))
		return IDN2_CONTEXTO_NO_RULE;
	  }
	  break;

	case CHECK_CONTEXTO_RULE:
	  {
	    size_t i;
	    int rc;

	    for (i = 0; i < *llen; i++)
	      {
		rc = _idn2_contexto_rule (*label, *llen, i);
		if (rc != IDN2_OK)
		  return rc;
	      }
	  }
	  break;

	case CHECK_UNASSIGNED:
	  {
	    size_t i;
	    for (i = 0; i < *llen; i++)
	      if (_idn2_unassigned_p ((*label)[i]))
		return IDN2_UNASSIGNED;
	  }
	  break;

	case CHECK_BIDI:
	  {
	    int rc = _idn2_bidi (*label, *llen);
	    if (rc != IDN2_OK)
	      return rc;
	  }
	  break;

	case ACE:
	  {
	    size_t i;
	    bool ascii = true;
	    int rc;

	    for (i = 0; i < *llen; i++)
	      if ((*label)[i] >= 0x80)
		ascii = false;

	    if (!ascii)
	      {
		char out[63];
		size_t tmpl;
		uint32_t *l;

		tmpl = sizeof (out);
		rc = _idn2_punycode_encode (*llen, *label, NULL,
					   &tmpl, out);
		if (rc != IDN2_OK)
		  return rc;

		l = malloc (sizeof (*l) * (tmpl + 4));
		if (l == NULL)
		  return IDN2_MALLOC;

		l[0] = 'x';
		l[1] = 'n';
		l[2] = '-';
		l[3] = '-';

		for (i = 0; i < tmpl; i++)
		  l[i + 4] = out[i];

		free (*label);
		*label = l;
		*llen = tmpl + 4;
	      }
	  }
	  break;

	case NFC:
	  {
	    uint32_t *p = u32_normalize (UNINORM_NFC, *label, *llen,
					 NULL, llen);
	    if (p == NULL)
	      return IDN2_NFC;
	    free (*label);
	    *label = p;
	  }
	  break;

	default:
	  return IDN2_OK;
	  break;
	}
    }

  return IDN2_OK;
}

static int
process (const int what[],
	 const uint32_t *src, size_t srclen,
	 uint32_t **dst, size_t *dstlen)
{
  uint32_t *tmp = u32_cpy_alloc (src, srclen);
  size_t tmplen = srclen;
  int rc;

  if (tmp == NULL)
    return IDN2_MALLOC;

  rc = process1 (what, &tmp, &tmplen);
  if (rc != IDN2_OK)
    {
      free (tmp);
      return rc;
    }

  *dst = tmp;
  *dstlen = tmplen;

  return IDN2_OK;
}

int
_idn2_label_u8 (const int what[],
		const uint8_t *src, size_t srclen,
		uint8_t **dst, size_t *dstlen)
{
  size_t plen, u32dstlen;
  uint32_t *p = u8_to_u32 (src, srclen, NULL, &plen);
  uint32_t *u32dst = NULL;
  int rc;

  if (p == NULL)
    {
      if (errno == ENOMEM)
	return IDN2_MALLOC;
      return IDN2_ENCODING_ERROR;
    }

  rc = process (what, p, plen, &u32dst, &u32dstlen);
  free (p);
  if (rc != IDN2_OK)
    return rc;

  *dst = u32_to_u8 (u32dst, u32dstlen, NULL, dstlen);

  if (*dst == NULL)
    return IDN2_MALLOC;

  return IDN2_OK;
}

int
_idn2_domain_u8 (const int what[], const uint8_t *src, uint8_t **dst)
{
  const uint8_t *p;

  *dst = NULL;

  if (src == NULL)
    return IDN2_OK;

  do
    {
      for (p = src; *p != '\0' && *p != '.'; p++)
	;

      {
	int rc;
	uint8_t *tmp;
	size_t tmplen;

	rc = _idn2_label_u8 (what, src, p - src, &tmp, &tmplen);
	if (rc != IDN2_OK)
	  return rc;

	if (*dst == NULL)
	  {
	    *dst = malloc (tmplen + 1);
	    if (*dst == NULL)
	      return IDN2_MALLOC;

	    memcpy (*dst, tmp, tmplen);
	    (*dst)[tmplen] = '\0';
	  }
	else
	  {
	    size_t l = strlen (*dst);
	    uint8_t *p = realloc (*dst, l + tmplen + 2);

	    if (p == NULL)
	      {
		free (*dst);
		return IDN2_MALLOC;
	      }

	    p[l] = '.';
	    memcpy (p + l + 1, tmp, tmplen);
	    p[l + tmplen + 1] = '\0';

	    *dst = p;
	  }
      }

      if (*p == '\0')
	break;

      src = p + 1;
    }
  while (*src);

  return IDN2_OK;
}
