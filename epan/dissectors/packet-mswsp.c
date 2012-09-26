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
#include "mswsp.h"

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

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
static int hf_mswsp_msg_ConnectIn_ClientVersion = -1;
static int hf_mswsp_msg_ConnectIn_ClientIsRemote = -1;
static int hf_mswsp_msg_ConnectIn_Blob1 = -1;
static int hf_mswsp_msg_ConnectIn_Blob2 = -1;
static int hf_mswsp_msg_ConnectIn_MachineName = -1;
static int hf_mswsp_msg_ConnectIn_UserName = -1;
static int hf_mswsp_msg_ConnectIn_PropSets_num = -1;
static int hf_mswsp_msg_ConnectIn_ExtPropSets_num = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean gPREF_HEX = FALSE;
/* Global sample port pref */
static guint gPORT_PREF = 1234;

/* Initialize the subtree pointers */
static gint ett_mswsp = -1;
static gint ett_mswsp_hdr = -1;
static gint ett_mswsp_msg = -1;
static gint ett_mswsp_pad = -1;
static gint ett_mswsp_propset_array[2];
static gint ett_mswsp_propset[8];
static gint ett_mswsp_prop[64];
static gint ett_mswsp_prop_colid[64];
static gint ett_mswsp_prop_value[64];

struct {
    guint propset_array;
    guint propset;
    guint prop;
    guint prop_colid;
    guint prop_value;
} ett_idx;

static int parse_padding(tvbuff_t *tvb, int offset, int alignment, proto_tree *pad_tree, const char *text)
{
    int padding = 0;
    if (offset % alignment) {
        padding = alignment - (offset % alignment);
        proto_tree_add_text(pad_tree, tvb, offset, padding, "%s (%d)", text ? text : "???", padding);
    }
    return padding;
}

static int read0(tvbuff_t *tvb _U_, int offset _U_, union vValue *v _U_, gboolean vector _U_)
{
    return 0;
}

static int read1(tvbuff_t *tvb, int offset, union vValue *v, gboolean vector)
{
    if (vector) {
        int num = tvb_get_letohl(tvb, offset);
        const guint8 *ptr = tvb_get_ptr(tvb, offset+4, num);
        v->vt_vector.len = num;
        v->vt_vector.vt_ui1 = se_memdup(ptr, num);
        return 4 + num;
    } else {
        v->vt_ui1 = tvb_get_guint8(tvb, offset);
        return 1;
   }
}

static int read2(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    if (vector) {
        int i, num = tvb_get_letohl(tvb, offset);
        guint16 *arr = se_alloc(2*num);
        offset += 4;

        for (i=0; i<num; i++) {
            arr[i] = tvb_get_letohs(tvb, offset);
            offset += 2;
        }

        v->vt_vector.len = num;
        v->vt_vector.vt_ui2 = arr;

        return 4 + 2*num;
    } else {
        v->vt_ui2 = tvb_get_letohs(tvb, offset);
        return 2;
    }
}

static int read4(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    if (vector) {
        int i, num = tvb_get_letohl(tvb, offset);
        guint32 *arr = se_alloc(4*num);
        offset += 4;

        for (i=0; i<num; i++) {
            arr[i] = tvb_get_letohl(tvb, offset);
            offset += 4;
        }

        v->vt_vector.len = num;
        v->vt_vector.vt_ui4 = arr;

        return 4 + 2*num;
    } else {
        v->vt_ui4 = tvb_get_letohl(tvb, offset);
        return 4;
    }
}

static int read8(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    if (vector) {
        int i, num = tvb_get_letohl(tvb, offset);
        guint64 *arr = se_alloc(8*num);
        offset += 4;

        for (i=0; i<num; i++) {
            arr[i] = tvb_get_letoh64(tvb, offset);
            offset += 8;
        }

        v->vt_vector.len = num;
        v->vt_vector.vt_ui8 = arr;

        return 4 + 8*num;
    } else {
        v->vt_ui8 = tvb_get_letoh64(tvb, offset);
        return 8;
    }
}

static int read_blob(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    if (vector) {
        /* invalid */
        return -1;
    } else {
        guint32 len = tvb_get_letohl(tvb, offset);
        const guint8 *data = tvb_get_ptr(tvb, offset + 4, len);

        v->vt_blob.size = len;
        v->vt_blob.data = se_memdup(data, len);

        return 4 + len;
    }
}

static int read_bstr(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    gint len;
    const guint8 *ptr;
    if (vector) {
        const int offset_in = offset;
        guint32 num = tvb_get_letohl(tvb, offset);
        struct data_str *data = se_alloc((num+1)*sizeof(struct data_str));
        int i;
        offset += 4;

        for (i=0; (unsigned)i<num; i++) {
            len = tvb_get_letohl(tvb, offset);
            offset += 4;
            ptr = tvb_get_ptr(tvb, offset, len);
            offset += len;

            data[i].len = len;
            data[i].str = se_strndup(ptr, len);

            if (offset % 4) {
                int padding = 4 - (offset % 4);
                offset += padding;
            }
        }

        v->vt_vector.len = num;
        v->vt_vector.vt_lpstr = data;

        return offset - offset_in;
    } else {
        len = tvb_get_letohl(tvb, offset);
        ptr = tvb_get_ptr(tvb, offset + 4, len);

        v->vt_blob.size = len;
        v->vt_blob.data = se_strndup(ptr, len);

        return 4 + len;
    }
}

static int read_lpstr(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    gint len;
    if (vector) {
        const int offset_in = offset;
        guint32 num = tvb_get_letohl(tvb, offset);
        struct data_str *data = se_alloc((num+1)*sizeof(struct data_str));
        int i;
        offset += 4;

        for (i=0; (unsigned)i<num; i++) {
            data[i].len = tvb_get_letohl(tvb, offset);
            offset += 4;

            data[i].str = tvb_get_seasonal_stringz(tvb, offset, &len);
            offset += len;

            if (offset % 4) {
                int padding = 4 - (offset % 4);
                offset += padding;
            }
        }
        v->vt_vector.len = num;
        v->vt_vector.vt_lpstr = data;
        return offset - offset_in;
    } else {
        v->vt_lpstr.len = tvb_get_letohl(tvb, offset);
        v->vt_lpstr.str = tvb_get_seasonal_stringz(tvb, offset + 4, &len);
        /* XXX test vt_lpstr.len == len */
        return 4 + len;
    }
}

static int read_lpwstr(tvbuff_t *tvb , int offset , union vValue *v, gboolean vector)
{
    gint len;
    gchar *str;
    if (vector) {
        const int offset_in = offset;
        guint32 num = tvb_get_letohl(tvb, offset);
        struct data_str *data = se_alloc((num+1)*sizeof(struct data_str));
        int i;
        offset += 4;

        for (i=0; (unsigned)i<num; i++) {
            data[i].len = tvb_get_letohl(tvb, offset);
            offset += 4;

            str = tvb_get_ephemeral_unicode_stringz(tvb, offset, &len, ENC_LITTLE_ENDIAN);
            data[i].str = se_strdup(str);
            offset += len;

            if (offset % 4) {
                int padding = 4 - (offset % 4);
                offset += padding;
            }
        }
        v->vt_vector.len = num;
        v->vt_vector.vt_lpstr = data;
        return offset - offset_in;
    } else {
        v->vt_lpwstr.len = tvb_get_letohl(tvb, offset);

        str = tvb_get_ephemeral_unicode_stringz(tvb, offset + 4, &len, ENC_LITTLE_ENDIAN);
        v->vt_lpwstr.str = se_strdup (str);

        return 4 + len;
    }
}



struct {
    enum vType vType;
    const char *str;
    int len;
    int (*read)(tvbuff_t *tvb, int offset, union vValue *vValue, gboolean vector);
} VT_TYPE[] = {
    {VT_EMPTY,   "VT_EMPTY",     0, read0},
    {VT_NULL,    "VT_NULL",      0, read0},
    {VT_I2,      "VT_I2",        2, read2},
    {VT_I4,      "VT_I4",        4, read4},
    {VT_R4,      "VT_R4",        4, read4},
    {VT_R8,      "VT_R8",        8, read8},
    {VT_CY,      "VT_CY",        8, read8},
    {VT_DATE,    "VT_DATE",      8, read8},
    {VT_BSTR,    "VT_BSTR",     -1, read_bstr},
    {VT_ERROR,   "VT_ERROR",     8, read8},
    {VT_BOOL,    "VT_BOOL",      2, read2},
    {VT_VARIANT, "VT_VARIANT",  -1, NULL},
    {VT_DECIMAL, "VT_DECIMAL",  16, NULL},
    {VT_I1,      "VT_I1",        1, read1},
    {VT_UI1,     "VT_UI1",       1, read1},
    {VT_UI2,     "VT_UI2",       2, read2},
    {VT_UI4,     "VT_UI4",       4, read4},
    {VT_I8,      "VT_I8",        8, read8},
    {VT_UI8,     "VT_UI8",       8, read8},
    {VT_INT,     "VT_INT",       4, read4},
    {VT_UINT,    "VT_UINT",      4, read4},
    {VT_LPSTR,   "VT_LPSTR",    -1, read_lpstr},
    {VT_LPWSTR,  "VT_LPWSTR",   -1, read_lpwstr},
    {VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR", -1, NULL},
    {VT_FILETIME, "VT_FILETIME", 8, read8},
    {VT_BLOB,     "VT_BLOB",    -1, read_blob},
    {VT_BLOB_OBJECT, "VT_BLOB_OBJECT", -1, read_blob},
    {VT_CLSID,    "VT_CLSID",   16, NULL},
};

static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                                     struct CBaseStorageVariant *value)
{
    const int offset_in = offset;
    int i, len;
    enum vType vType;
    gboolean is_vt_vector, is_vt_array;
    proto_item *ti;

    vType = tvb_get_letohs(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 2, "vType");
    offset += 2;

    is_vt_vector = !!(vType & VT_VECTOR);
    is_vt_array  = !!(vType & VT_ARRAY);

    value->vType = vType & 0xff;
    value->vType_high = vType & 0xff00;

    value->vData1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "vData1: %d", value->vData1);
    offset += 1;

    value->vData2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "vData2: %d", value->vData2);
    offset += 1;

    fprintf(stderr, "VTYPE: 0x%04x\n", vType);
    for (i=0; (unsigned)i<array_length(VT_TYPE); i++) {
        if (value->vType == VT_TYPE[i].vType) {
            break;
        }
    }
    if (i == array_length(VT_TYPE)) {
        goto not_supported;
    }

    proto_item_append_text(ti, ": %s", VT_TYPE[i].str);
    if (is_vt_vector) {
        proto_item_append_text(ti, "|VT_VECTOR");
    }
    if (is_vt_array) {
        proto_item_append_text(ti, "|VT_ARRAY");
        goto not_supported;
    }

    if (VT_TYPE[i].read == NULL) {
        goto not_supported;
    }

    len = VT_TYPE[i].read(tvb, offset, &value->vValue, is_vt_vector);
    if (len == -1) {
        goto not_supported;
    }
    ti = proto_tree_add_text(tree, tvb, offset, len, "vValue");
    offset += len;

    if (is_vt_vector ) {
        proto_item_append_text(ti, " [%d]", value->vValue.vt_vector.len);
    }

done:
    return offset - offset_in;
    not_supported:
        proto_item_append_text(ti, ": sorry, vType %02x not handled yet!", (unsigned)vType);
        return offset - offset_in;
}

enum {
    DBKIND_GUID_NAME = 0,
    DBKIND_GUID_PROPID = 1
};

static int parse_CDbColId(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree)
{
    const int offset_in = offset;
    int len;
    guint32 eKind, ulId;
    e_guid_t guid;
    const char *guid_str;
    static const char *KIND[] = {"DBKIND_GUID_NAME", "DBKIND_GUID_PROPID"};
    proto_item *tree_item = proto_tree_get_parent(tree);

    eKind = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "eKind: %s (%u)", eKind < 2 ? KIND[eKind] : "???", eKind);
    offset += 4;

    len = parse_padding(tvb, offset, 8, pad_tree, "paddingGuidAlign");
    DISSECTOR_ASSERT(len <= 8);
    offset += len;

    tvb_get_letohguid(tvb, offset, &guid);
    guid_str =  guid_to_str(&guid);
    proto_tree_add_text(tree, tvb, offset, 16, "GUID: %s", guid_str);
//    proto_tree_add_guid(tree, , tvb, offset, 16, &guid);
    proto_item_append_text(tree_item, ": {%s}", guid_str);
    offset += 16;

    ulId = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "ulId: %d", ulId);
    offset += 4;

    if (eKind == DBKIND_GUID_NAME) {
        char *name;
        len = ulId; //*2 ???
        name = tvb_get_unicode_string(tvb, offset, len, ENC_LITTLE_ENDIAN);
        proto_tree_add_text(tree, tvb, offset, len, "vString: \"%s\"", name);
        proto_item_append_text(tree_item, " \"%s\"", name);
        offset += len;
    } else if (eKind == DBKIND_GUID_PROPID) {
        proto_item_append_text(tree_item, " %08x", ulId);
    } else {
        proto_item_append_text(tree_item, "<INVALID>");
    }

    return offset - offset_in;
}

static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree)
{
    const int offset_in = offset;
    int len;
    guint32 id, opt, status;
    struct CBaseStorageVariant value;
    proto_item *ti, *tree_item = proto_tree_get_parent(tree);
    proto_tree *tr;

    id = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "DBPROPID: %08x", id);
    offset += 4;
    proto_item_append_text(tree_item, " Id: 0x%08x", id);

    opt = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "DBPROPOPTIONS: %08x", opt);
    offset += 4;

    status = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "DBPROPSTATUS: %08x", status);
    offset += 4;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "colid");
    tr = proto_item_add_subtree(ti, ett_mswsp_prop_colid[ett_idx.prop_colid++]); //???
    DISSECTOR_ASSERT(ett_idx.prop_colid <= array_length(ett_mswsp_prop_colid));
    len = parse_CDbColId(tvb, offset, tr, pad_tree);
    proto_item_set_len(ti, len);
    offset += len;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "vValue");
    tr = proto_item_add_subtree(ti, ett_mswsp_prop_value[ett_idx.prop_value++]); //???
    DISSECTOR_ASSERT(ett_idx.prop_value <= array_length(ett_mswsp_prop_value));
    len = parse_CBaseStorageVariant(tvb, offset, tr, pad_tree, &value);
    proto_item_set_len(ti, len);
    offset += len;

    fprintf(stderr, "PROP: oi: %d oo: %d doff %d\n", offset_in, offset, offset - offset_in);
    return offset - offset_in;
}

static struct {
    const char *guid;
    const char *def;
    const char *desc;
} GuidPropertySet[] = {
    {"a9bd1526-6a80-11d0-8c9d-0020af1d740e", "DBPROPSET_FSCIFRMWRK_EXT", "File system content index framework"},
    {"a7ac77ed-f8d7-11ce-a798-0020f8008025", "DBPROPSET_QUERYEXT", "Query extension"},
    {"afafaca5-b5d1-11d0-8c62-00c04fc2db8d", "DBPROPSET_CIFRMWRKCORE_EXT", "Content index framework core"},
};


static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree)
{
    const int offset_in = offset;
    int len, i, num;
    e_guid_t guid;
    const char *guid_str;
    proto_item *ti, *tree_item = proto_tree_get_parent(tree);

    tvb_get_letohguid(tvb, offset, &guid);
    guid_str =  guid_to_str(&guid);
    ti = proto_tree_add_text(tree, tvb, offset, 16, "guidPropertySet: %s", guid_str);
    offset += 16;
    for (i=0; (unsigned)i<array_length(GuidPropertySet); i++) {
        if (strcasecmp(GuidPropertySet[i].guid, guid_str) == 0) {
            proto_item_append_text(ti, " (%s)", GuidPropertySet[i].def);
            proto_item_append_text(tree_item, " %s (%s)",
                                   GuidPropertySet[i].def,
                                   GuidPropertySet[i].desc);
            break;
        }
    }
    if (i==array_length(GuidPropertySet)) {
         proto_item_append_text(tree_item, " {%s}", guid_str);
    }

    len = parse_padding(tvb, offset, 4, pad_tree, "guidPropertySet");
    offset += len;

    num = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cProperties: %d", num);
    offset += 4;
    proto_item_append_text(tree_item, " Size: %d", num);

    for (i = 0; i<num; i++) {
        proto_item *ti;
        proto_tree *tr;

        len = parse_padding(tvb, offset, 4, pad_tree, "aProp");
        offset += len;

        ti = proto_tree_add_text(tree, tvb, offset, 0, "aProp[%d]", i);
        tr = proto_item_add_subtree(ti, ett_mswsp_prop[ett_idx.prop++]); //???
        DISSECTOR_ASSERT(ett_idx.prop <= array_length(ett_mswsp_prop));
        len = parse_CDbProp(tvb, offset, tr, pad_tree);
        proto_item_set_len(ti, len);
        offset += len;
    }
    return offset - offset_in;
}

static int parse_PropertySetArray(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree, int size_offset)
{
    const int offset_in = offset;
    guint32 size, num;
    int len, i;

    size = tvb_get_letoh24(tvb, size_offset);
    proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_Blob1, tvb,
                        size_offset, 4, ENC_LITTLE_ENDIAN);

    num = tvb_get_letoh24(tvb, offset);
    proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_PropSets_num, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    for (i = 0; i < (int)num; i++) {
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "PropertySet[%d]", i);
        proto_tree *tr = proto_item_add_subtree(ti, ett_mswsp_propset[ett_idx.propset++]);
        DISSECTOR_ASSERT(ett_idx.propset <= array_length(ett_mswsp_propset));
        len = parse_CDbPropSet(tvb, offset, tr, pad_tree);
        proto_item_set_len(ti, len);
        offset += len;
    }

    fprintf(stderr, "ARRAY: oi: %d oo: %d doff %d size: %d\n", offset_in, offset, offset - offset_in, size);
    return size;
}

/* Code to actually dissect the packets */

static int dissect_CPMConnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in)
{
    proto_item *ti;
    proto_tree *tree;
    gint offset = 16;
    guint len;

    ZERO_STRUCT(ett_idx);

    ti = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, 17, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mswsp_msg);
    proto_item_set_text(ti, "CPMConnect%s", in ? "In" : "Out");
    col_append_str(pinfo->cinfo, COL_INFO, "Connect");
    if (in) {
        guint32 blob_size1_off, blob_size2_off;
        proto_tree *pad_tree, *tr;

        ti = proto_tree_add_text(tree, tvb, offset, 0, "Padding");
        pad_tree = proto_item_add_subtree(ti, ett_mswsp_pad);

        proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_ClientVersion, tvb,
                            offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_ClientIsRemote, tvb,
                            offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* _cbBlob1 */
        blob_size1_off = offset;
        offset += 4;

        len = parse_padding(tvb, offset, 8, pad_tree, "_paddingcbBlob2");
        offset += len;
        DISSECTOR_ASSERT(len == 4);

        /* _cbBlob2 */
        blob_size2_off = offset;
        offset += 4;

        len = parse_padding(tvb, offset, 16, pad_tree, "_padding");
        offset += len;
        DISSECTOR_ASSERT(len == 12);

        len = tvb_unicode_strsize(tvb, offset);
        ti = proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_MachineName, tvb,
                                 offset, len, ENC_UTF_16);
        /*This shouldnt be necessary, is this a bug or is there some GUI setting I've missed?*/
        proto_item_set_text(ti, "Remote machine: %s",
                            tvb_get_unicode_string(tvb, offset, len, ENC_LITTLE_ENDIAN));
        offset += len;

        len = tvb_unicode_strsize(tvb, offset);
        ti = proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_UserName, tvb,
                                 offset, len, ENC_UTF_16);
        proto_item_set_text(ti, "User: %s", tvb_get_unicode_string(tvb, offset, len, ENC_LITTLE_ENDIAN));
        offset += len;

        len = parse_padding(tvb, offset, 8, pad_tree, "_paddingcPropSets");
        offset += len;
        DISSECTOR_ASSERT((offset % 8) == 0);

        ti = proto_tree_add_text(tree, tvb, offset, 0, "PropSets");
        tr = proto_item_add_subtree(ti, ett_mswsp_propset_array[0]);
        len = parse_PropertySetArray(tvb, offset, tr, pad_tree, blob_size1_off);
        proto_item_set_len(ti, len);
        offset += len;

        len = parse_padding(tvb, offset, 8, pad_tree, "paddingExtPropset");
        offset += len;
        DISSECTOR_ASSERT((offset % 8) == 0);

        ti = proto_tree_add_text(tree, tvb, offset, 0, "ExtPropset");
        tr = proto_item_add_subtree(ti, ett_mswsp_propset_array[1]);
        len = parse_PropertySetArray(tvb, offset, tr, pad_tree, blob_size2_off);
        proto_item_set_len(ti, len);
        offset += len;

        len = parse_padding(tvb, offset, 8, pad_tree, NULL);
        offset += len;
//        DISSECTOR_ASSERT(offset == (int)tvb_length(tvb));
        fprintf(stderr, "len: %d offset: %d length: %d\n", len, offset, (int)tvb_length(tvb));

        /* make "Padding" the last item */
        proto_tree_move_item(tree, ti, proto_tree_get_parent(pad_tree));
    }
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
    }

    fn(tvb, pinfo, mswsp_tree, in);

/* Return the amount of data this dissector was able to dissect */
    return tvb_length(tvb);
}


static void register_ett_array(gint arr[], int num)
{
    int i;
    gint *ett[num];
    for (i=0; i<num; i++) {
        arr[i] = -1;
        ett[i] = &arr[i];
    }
    proto_register_subtree_array(ett, num);
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
			{ "Msg id", "mswsp.hdr.id",
                          FT_UINT32, BASE_HEX , VALS(msg_ids), 0,
			"Message id", HFILL }
		},
		{ &hf_mswsp_hdr_status,
			{ "Status", "mswsp.hdr.status",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Status", HFILL }
		},
		{ &hf_mswsp_hdr_checksum,
			{ "checksum", "mswsp.hdr.checksum",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Checksum", HFILL }
		},
		{ &hf_mswsp_hdr_reserved,
			{ "Reserved", "mswsp.hdr.reserved",
			FT_UINT32, BASE_HEX , NULL, 0,
			"Reserved", HFILL }
		},
		{ &hf_mswsp_msg,
			{ "msg", "mswsp.msg",
			FT_NONE, BASE_NONE , NULL, 0,
			"Message", HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_ClientVersion,
                  { "Version", "mswsp.ConnectIn.version",
                    FT_UINT32, BASE_HEX , NULL, 0,
                    "Checksum",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_ClientIsRemote,
                  { "Remote", "mswsp.ConnectIn.isRemote",
                    FT_BOOLEAN, BASE_HEX , NULL, 0,
                    "Client is remote",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_Blob1,
                  { "Size", "mswsp.ConnectIn.propset.size",
                    FT_UINT32, BASE_DEC , NULL, 0,
                    "Size of PropSet fields",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_Blob2,
                  { "Size", "mswsp.ConnectIn.extpropset.size",
                    FT_UINT32, BASE_DEC , NULL, 0,
                    "Size of ExtPropSet fields",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_MachineName,
                  { "Remote machine", "mswsp.ConnectIn.machine",
                    FT_STRINGZ, BASE_NONE , NULL, 0,
                    "Name of remote machine",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_UserName,
                  { "User", "mswsp.ConnectIn.user",
                    FT_STRINGZ, BASE_NONE , NULL, 0,
                    "Name of remote user",HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_PropSets_num,
                  { "Num", "mswsp.ConnectIn.propset.num",
                    FT_UINT32, BASE_DEC , NULL, 0,
                    "Number of Property Sets", HFILL }
		},
		{ &hf_mswsp_msg_ConnectIn_ExtPropSets_num,
                  { "Num", "mswsp.ConnectIn.extpropset.num",
                    FT_UINT32, BASE_DEC , NULL, 0,
                    "Number of extended Property Sets", HFILL }
		},

	};

/* Setup protocol subtree array */
	static gint *ett[] = {
            &ett_mswsp,
            &ett_mswsp_hdr,
            &ett_mswsp_msg,
            &ett_mswsp_pad,
	};

/* Register the protocol name and description */
	proto_mswsp = proto_register_protocol("Windows Search Protocol",
                                              "MS-WSP", "mswsp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mswsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        register_ett_array(ett_mswsp_propset_array, array_length(ett_mswsp_propset_array));
        register_ett_array(ett_mswsp_propset, array_length(ett_mswsp_propset));
        register_ett_array(ett_mswsp_prop, array_length(ett_mswsp_prop));
        register_ett_array(ett_mswsp_prop_colid, array_length(ett_mswsp_prop_colid));
        register_ett_array(ett_mswsp_prop_value, array_length(ett_mswsp_prop_value));


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
