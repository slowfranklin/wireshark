/* packet-mswsp.c
 * Routines for PROTONAME dissection
 * Copyright 2012, Gregor Beck <gregor.beck@sernet.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Include only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
/*
 * #include "packet-mswsp.h"
 */

/* Forward declaration we need below (if using proto_reg_handoff...
   as a prefs callback)       */
void proto_reg_handoff_mswsp(void);

/* Initialize the protocol and registered fields */
static int proto_mswsp = -1;
static int hf_mswsp_bdy = -1;
static int hf_mswsp_hdr = -1;
static int hf_mswsp_hdr_msg = -1;
static int hf_mswsp_hdr_status = -1;
static int hf_mswsp_hdr_crc = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port pref */
static guint gPORT_PREF = 1234;

/* Initialize the subtree pointers */
static gint ett_mswsp = -1;
static gint ett_mswsp_hdr = -1;
static gint ett_mswsp_bdy = -1;

/* Code to actually dissect the packets */
static int
dissect_mswsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    fprintf(stderr, "dissect_mswsp: %s dceidx: %d\n",
            pinfo->dcerpc_procedure_name ? pinfo->dcerpc_procedure_name : "<NULL>",
            (int)pinfo->dcectxid);

/*  First, if at all possible, do some heuristics to check if the packet cannot
 *  possibly belong to your protocol.  This is especially important for
 *  protocols directly on top of TCP or UDP where port collisions are
 *  common place (e.g., even though your protocol uses a well known port,
 *  someone else may set up, for example, a web server on that port which,
 *  if someone analyzed that web server's traffic in Wireshark, would result
 *  in Wireshark handing an HTTP packet to your dissector).  For example:
 */

    if (strcmp(pinfo->dcerpc_procedure_name, "File: MsFteWds") != 0) {
        return 0;
    }

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "mswsp");

/* This field shows up as the "Info" column in the display; you should use
   it, if possible, to summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. See section 1.5
   for more information.

   If you are setting the column to a constant string, use "col_set_str()",
   as it's more efficient than the other "col_set_XXX()" calls.

   If you're setting it to a string you've constructed, or will be
   appending to the column later, use "col_add_str()".

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments.  Don't use "col_add_fstr()" with a format
   string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   more efficient than "col_add_fstr()".

   If you will be fetching any data from the packet before filling in
   the Info column, clear that column first, in case the calls to fetch
   data from the packet throw an exception because they're fetching data
   past the end of the packet, so that the Info column doesn't have data
   left over from the previous dissector; do

	col_clear(pinfo->cinfo, COL_INFO);

   */

    col_add_str(pinfo->cinfo, COL_INFO, "WSP");

/* A protocol dissector may be called in 2 different ways - with, or
   without a non-null "tree" argument.

   If the proto_tree argument is null, Wireshark does not need to use
   the protocol tree information from your dissector, and therefore is
   passing the dissector a null "tree" argument so that it doesn't
   need to do work necessary to build the protocol tree.

   In the interest of speed, if "tree" is NULL, avoid building a
   protocol tree and adding stuff to it, or even looking at any packet
   data needed only if you're building the protocol tree, if possible.

   Note, however, that you must fill in column information, create
   conversations, reassemble packets, do calls to "expert" functions,
   build any other persistent state needed for dissection, and call
   subdissectors regardless of whether "tree" is NULL or not.

   This might be inconvenient to do without doing most of the
   dissection work; the routines for adding items to the protocol tree
   can be passed a null protocol tree pointer, in which case they'll
   return a null item pointer, and "proto_item_add_subtree()" returns
   a null tree pointer if passed a null item pointer, so, if you're
   careful not to dereference any null tree or item pointers, you can
   accomplish this by doing all the dissection work.  This might not
   be as efficient as skipping that work if you're not building a
   protocol tree, but if the code would have a lot of tests whether
   "tree" is null if you skipped that work, you might still be better
   off just doing all that work regardless of whether "tree" is null
   or not.

   Note also that there is no guarantee, the first time the dissector is
   called, whether "tree" will be null or not; your dissector must work
   correctly, building or updating whatever state information is
   necessary, in either case. */
    if (tree) {
        proto_item *ti=NULL, *hti=NULL, *bti=NULL;
        proto_tree *mswsp_tree=NULL, *mswsp_hdr_tree=NULL, *mswsp_bdy_tree=NULL;

        ti = proto_tree_add_item(tree, proto_mswsp, tvb, 0, -1, ENC_NA);

        mswsp_tree = proto_item_add_subtree(ti, ett_mswsp);

        hti = proto_tree_add_item(mswsp_tree, hf_mswsp_hdr, tvb, 0, 16, ENC_NA);
        mswsp_hdr_tree = proto_item_add_subtree(hti, ett_mswsp_hdr);

        proto_tree_add_item(mswsp_hdr_tree,
                            hf_mswsp_hdr_msg, tvb, 0, 4, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(mswsp_hdr_tree,
                            hf_mswsp_hdr_status, tvb, 4, 4, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(mswsp_hdr_tree,
                            hf_mswsp_hdr_crc, tvb, 8, 4, ENC_LITTLE_ENDIAN);

        /* proto_tree_add_item(mswsp_hdr_tree, */
        /*                     hf_mswsp_hdr_reserved, tvb, 12, 4, ENC_LITTLE_ENDIAN); */

        if (tvb_length(tvb) > 16) {
            bti = proto_tree_add_item(mswsp_tree, hf_mswsp_bdy, tvb, 17, -1, ENC_NA);

            mswsp_bdy_tree = proto_item_add_subtree(bti, ett_mswsp_bdy);
        }
    }

/* If this protocol has a sub-dissector call it here, see section 1.8 */

/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_mswsp(void)
{
	module_t *mswsp_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
        static const value_string msg_ids[] = {
            {0x000000C8, "CPMConnect"},                /* In/Out */
            {0x000000C9, "CPMDisconnect"},
            {0x000000CA, "CPMCreateQuery"},            /* In/Out */
            {0x000000CB, "CPMFreeCursor"},             /* In/Out */
            {0x000000CC, "CPMGetRows"},                /* In/Out */
            {0x000000CD, "CPMRatioFinished"},          /* In/Out */
            {0x000000CE, "CPMCompareBmk"},             /* In/Out */
            {0x000000CF, "CPMGetApproximatePosition"}, /* In/Out */
            {0x000000D0, "CPMSetBindingsIn"},
            {0x000000D1, "CPMGetNotify"},
            {0x000000D2, "CPMSendNotifyOut"},
            {0x000000D7, "CPMGetQueryStatusIn"},       /* In/Out */
            {0x000000D9, "CPMCiStateInOut"},
            {0x000000E4, "CPMFetchValue"},             /* In/Out */
            {0x000000E7, "CPMGetQueryStatusEx"},       /* In/Out */
            {0x000000E8, "CPMRestartPositionIn"},
            {0x000000EC, "CPMSetCatStateIn"},          /* (not supported) */
            {0x000000F1, "CPMGetRowsetNotify"},        /* In/Out */
            {0x000000F2, "CPMFindIndices"},            /* In/Out */
            {0x000000F3, "CPMSetScopePrioritization"}, /* In/Out */
            {0x000000F4, "CPMGetScopeStatistics"},     /* In/Out */
        };

	static hf_register_info hf[] = {
		{ &hf_mswsp_hdr,
			{ "Header",           "mswsp.hdr",
			FT_NONE, BASE_NONE , NULL, 0,
			"Message header", HFILL }
		},
		{ &hf_mswsp_bdy,
			{ "Body",           "mswsp.body",
			FT_NONE, BASE_NONE , NULL, 0,
			"Message body", HFILL }
		},
		{ &hf_mswsp_hdr_msg,
			{ "msg",           "mswsp.hdr.msg",
                          FT_UINT32, BASE_HEX , VALS(msg_ids), 0,
			"Message id", HFILL }
		},
		{ &hf_mswsp_hdr_status,
			{ "status",           "mswsp.hdr.status",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Header status", HFILL }
		},
		{ &hf_mswsp_hdr_crc,
			{ "crc",           "mswsp.hdr.crc",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Header checksum", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
            &ett_mswsp,
            &ett_mswsp_hdr,
            &ett_mswsp_bdy,
	};

/* Register the protocol name and description */
	proto_mswsp = proto_register_protocol("Windows Search Protocol",
                                              "MS-WSP", "mswsp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mswsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* Register preferences module (See Section 2.6 for more on preferences) */
/* (Registration of a prefs callback is not required if there are no     */
/*  prefs-dependent registration functions (eg: a port pref).            */
/*  See proto_reg_handoff below.                                         */
/*  If a prefs callback is not needed, use NULL instead of               */
/*  proto_reg_handoff_mswsp in the following).                     */
	mswsp_module = prefs_register_protocol(proto_mswsp,
	    proto_reg_handoff_mswsp);

/* Register preferences module under preferences subtree.
   Use this function instead of prefs_register_protocol if you want to group
   preferences of several protocols under one preferences subtree.
   Argument subtree identifies grouping tree node name, several subnodes can be
   specified using slash '/' (e.g. "OSI/X.500" - protocol preferences will be
   accessible under Protocols->OSI->X.500-><PROTOSHORTNAME> preferences node.
*/
  /* mswsp_module = prefs_register_protocol_subtree(subtree, */
  /*      proto_mswsp, proto_reg_handoff_mswsp); */

/* Register a sample preference */
	prefs_register_bool_preference(mswsp_module, "show_hex",
	     "Display numbers in Hex",
	     "Enable to display numerical values in hexadecimal.",
	     &gPREF_HEX);

/* Register a sample port preference   */
	prefs_register_uint_preference(mswsp_module, "tcp.port", "mswsp TCP Port",
	     " mswsp TCP port if other than the default",
	     10, &gPORT_PREF);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these
   routines and create the code that calls these routines.

   If this function is registered as a prefs callback (see prefs_register_protocol
   above) this function is also called by preferences whenever "Apply" is pressed;
   In that case, it should accommodate being called more than once.

   Simple form of proto_reg_handoff_mswsp which can be used if there are
   no prefs-dependent registration function calls.
 */

void
proto_reg_handoff_mswsp(void)
{
    heur_dissector_add("smb_transact", dissect_mswsp, proto_mswsp);
    heur_dissector_add("smb2_heur_subdissectors", dissect_mswsp, proto_mswsp);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
