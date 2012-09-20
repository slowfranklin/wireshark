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

#include "packet-smb.h"
#include "packet-smb2.h"

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
static int hf_mswsp_msg = -1;
static int hf_mswsp_hdr = -1;
static int hf_mswsp_hdr_msg = -1;
static int hf_mswsp_hdr_status = -1;
static int hf_mswsp_hdr_checksum = -1;
static int hf_mswsp_hdr_reserved = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port pref */
static guint gPORT_PREF = 1234;

/* Initialize the subtree pointers */
static gint ett_mswsp = -1;
static gint ett_mswsp_hdr = -1;
static gint ett_mswsp_msg = -1;

/* Code to actually dissect the packets */

static int dissect_CPMConnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean in)
{
    col_append_str(pinfo->cinfo, COL_INFO, "Connect");
    return tvb_length(tvb);
}

static int dissect_CPMDisconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "Disconnect");
    return tvb_length(tvb);
}

static int dissect_CPMCreateQuery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "CreateQuery");
    return tvb_length(tvb);
}

static int dissect_CPMFreeCursor(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "FreeCursor");
    return tvb_length(tvb);
}

static int dissect_CPMGetRows(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetRows");
    return tvb_length(tvb);
}

static int dissect_CPMRatioFinished(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "RatioFinished");
    return tvb_length(tvb);
}

static int dissect_CPMCompareBmk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "CompareBmk");
    return tvb_length(tvb);
}

static int dissect_CPMGetApproximatePosition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetApproximatePosition");
    return tvb_length(tvb);
}

static int dissect_CPMSetBindings(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "SetBindings");
    return tvb_length(tvb);
}

static int dissect_CPMGetNotify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetNotify");
    return tvb_length(tvb);
}

static int dissect_CPMSendNotifyOut(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "SendNotify");
    return tvb_length(tvb);
}

static int dissect_CPMGetQueryStatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetQueryStatus");
    return tvb_length(tvb);
}

static int dissect_CPMCiState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "CiState");
    return tvb_length(tvb);
}

static int dissect_CPMFetchValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "FetchValue");
    return tvb_length(tvb);
}

static int dissect_CPMGetQueryStatusEx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetQueryStatusEx");
    return tvb_length(tvb);
}

static int dissect_CPMRestartPosition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "RestartPosition");
    return tvb_length(tvb);
}

static int dissect_CPMSetCatState(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "SetCatState");
    return tvb_length(tvb);
}

static int dissect_CPMGetRowsetNotify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetRowsetNotify");
    return tvb_length(tvb);
}

static int dissect_CPMFindIndices(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "FindIndices");
    return tvb_length(tvb);
}

static int dissect_CPMSetScopePrioritization(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "SetScopePrioritization");
    return tvb_length(tvb);
}

static int dissect_CPMGetScopeStatistics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "GetScopeStatistics");
    return tvb_length(tvb);
}


int
dissect_mswsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean in)
{
    proto_tree *mswsp_tree = NULL;
    struct {
        guint32 msg;
        guint32 status;
        guint32 checksum;
        guint32 reserved;
    } hdr;
    int (*fn)(tvbuff_t*, packet_info*, proto_tree*, gboolean);

    if (tvb_length(tvb) < 16) {
        return 0;
    }

    hdr.msg = tvb_get_letoh24(tvb, 0);

    switch(hdr.msg) {
    case 0xC8:
        fn = dissect_CPMConnect;
        break;
    case 0xC9:
        fn = dissect_CPMDisconnect;
        break;
    case 0xCA:
        fn = dissect_CPMCreateQuery;
        break;
    case 0xCB:
        fn = dissect_CPMFreeCursor;
        break;
    case 0xCC:
        fn = dissect_CPMGetRows;
        break;
    case 0xCD:
        fn = dissect_CPMRatioFinished;
        break;
    case 0xCE:
        fn = dissect_CPMCompareBmk;
        break;
    case 0xCF:
        fn = dissect_CPMGetApproximatePosition;
        break;
    case 0xD0:
        fn = dissect_CPMSetBindings;
        break;
    case 0xD1:
        fn = dissect_CPMGetNotify;
        break;
    case 0xD2:
        fn = dissect_CPMSendNotifyOut;
        break;
    case  0xD7:
        fn = dissect_CPMGetQueryStatus;
        break;
    case  0xD9:
        fn = dissect_CPMCiState;
        break;
    case  0xE4:
        fn = dissect_CPMFetchValue;
        break;
    case  0xE7:
        fn = dissect_CPMGetQueryStatusEx;
        break;
    case  0xE8:
        fn = dissect_CPMRestartPosition;
        break;
    case  0xEC:
        fn = dissect_CPMSetCatState;
        break;
    case  0xF1:
        fn = dissect_CPMGetRowsetNotify;
        break;
    case  0xF2:
        fn = dissect_CPMFindIndices;
        break;
    case  0xF3:
        fn = dissect_CPMSetScopePrioritization;
        break;
    case  0xF4:
        fn = dissect_CPMGetScopeStatistics;
        break;
    default:
        return 0;
    }

    hdr.status = tvb_get_letoh24(tvb, 4);
    hdr.checksum = tvb_get_letoh24(tvb, 8);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS-WSP");
/*    col_clear(pinfo->cinfo, COL_INFO); */

    col_set_str(pinfo->cinfo, COL_INFO, "WSP ");
    col_append_str(pinfo->cinfo, COL_INFO, in ? "Request: " : "Response: ");

    if (tree) {
        proto_tree *hdr_tree;
        proto_item *ti, *hti;

        ti = proto_tree_add_item(tree, proto_mswsp, tvb, 0, -1, ENC_NA);
        mswsp_tree = proto_item_add_subtree(ti, ett_mswsp);

        hti = proto_tree_add_item(mswsp_tree, hf_mswsp_hdr, tvb, 0, 16, ENC_NA);
        hdr_tree = proto_item_add_subtree(hti, ett_mswsp_hdr);

        proto_tree_add_item(hdr_tree, hf_mswsp_hdr_msg, tvb,
                            0, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(hdr_tree, hf_mswsp_hdr_status,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(hdr_tree, hf_mswsp_hdr_checksum,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(hdr_tree, hf_mswsp_hdr_reserved, tvb,
                            12, 4, ENC_LITTLE_ENDIAN);
        /* if (tvb_length(tvb) > 16) { */
        /*     bti = proto_tree_add_item(mswsp_tree, hf_mswsp_bdy, tvb, 17, -1, ENC_NA); */

        /*     mswsp_bdy_tree = proto_item_add_subtree(bti, ett_mswsp_msg); */
        /* } */
    }

    fn(tvb, pinfo, mswsp_tree, in);

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
		{ &hf_mswsp_hdr_msg,
			{ "msg", "mswsp.hdr.msg",
                          FT_UINT32, BASE_HEX , VALS(msg_ids), 0,
			"Message id", HFILL }
		},
		{ &hf_mswsp_hdr_status,
			{ "status", "mswsp.hdr.status",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Status", HFILL }
		},
		{ &hf_mswsp_hdr_checksum,
			{ "checksum", "mswsp.hdr.checksum",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Checksum", HFILL }
		},
		{ &hf_mswsp_hdr_reserved,
			{ "crc", "mswsp.hdr.reserved",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Reserved", HFILL }
		},
		{ &hf_mswsp_msg,
			{ "msg", "mswsp.msg",
			FT_NONE, BASE_NONE , NULL, 0,
			"Message", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
            &ett_mswsp,
            &ett_mswsp_hdr,
            &ett_mswsp_msg,
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

static int dissect_mswsp_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    smb_info_t *si = pinfo->private_data;
    gboolean in = si->request;

    fprintf(stderr, "dissect_mswsp_smb %d <> %d : op %02x %s %s type: %d\n",
            pinfo->fd->num, si->tid,
            si->cmd,
            pinfo->dcerpc_procedure_name ? pinfo->dcerpc_procedure_name : "<NULL>",
            in ? "Request" : "Response", si->tid);


    if (strcmp(pinfo->dcerpc_procedure_name, "File: MsFteWds") != 0) {
        return 0;
    }

    return dissect_mswsp(tvb, pinfo, tree, in);
}


static int dissect_mswsp_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    smb2_info_t *si = pinfo->private_data;
    gboolean in = !(si->flags & SMB2_FLAGS_RESPONSE);

//si->tree->share_type == SMB2_SHARE_TYPE_PIPE
//si->tree->connect_frame

    fprintf(stderr, "dissect_mswsp %d <> %d : op %02x %s %s type: %d extra_file: %s\n",
            pinfo->fd->num, si->tree ? (int)si->tree->connect_frame : -1,
            si->opcode,
            pinfo->dcerpc_procedure_name ? pinfo->dcerpc_procedure_name : "<NULL>",
            in ? "Request" : "Response", si->tree ? si->tree->share_type : -1,
            si->saved ? (si->saved->extra_info_type == SMB2_EI_FILENAME ? (char*)si->saved->extra_info : "<OTHER>") : "<NONE>"
        );


    if (strcmp(pinfo->dcerpc_procedure_name, "File: MsFteWds") != 0) {
        return 0;
    }

    return dissect_mswsp(tvb, pinfo, tree, in);
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
    heur_dissector_add("smb_transact", dissect_mswsp_smb, proto_mswsp);
    heur_dissector_add("smb2_heur_subdissectors", dissect_mswsp_smb2, proto_mswsp);
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
