/*
 * Copyright 2006-2012, Ubiquiti Networks, Inc. <gpl@ubnt.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of other contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

//#include <ber/ber.h>
//#include <debug/memory.h>
#include <debug/log.h>
//#include <abz/typedefs.h>
#include <abz/error.h>

#include <tinysnmp/tinysnmp.h>
#include <tinysnmp/agent/module.h>
#include <tinysnmp/agent/odb.h>

#include "ubnt-airos.h"

static int
ubnt_mib_update(struct odb **odb) {
	abz_clear_error();
	odb_destroy(odb);

	log_printf(LOG_VERBOSE, "updating airos table\n");
	int rc = update_airos_table(odb, 1);
	log_printf(LOG_VERBOSE,"done. rc: %d\n", rc);

	return rc;
}

extern void airos_cleanup_stats(void);

static void ubnt_mib_destroy(void)
{
	airos_cleanup_stats();
}

static const uint32_t ubnt_oid[] = { 6, 43, 6, 1, 4, 1, 41112 };

struct module module = {
	.name    = "ubnt",
	.descr   = "Ubiquiti Networks MIB module ",
	.mod_oid = ubnt_oid,
	.con_oid = ubnt_oid,
	.parse   = NULL,
	.open    = NULL,
	.update  = ubnt_mib_update,
	.close   = ubnt_mib_destroy
};

