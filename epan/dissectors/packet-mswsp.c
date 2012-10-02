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
#include <stdbool.h>

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
static int hf_mswsp_msg_Connect_Version = -1;
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

static gint ett_mswsp_restriction = -1;
static gint ett_mswsp_restriction_node = -1;
static gint ett_mswsp_property_restriction = -1;
static gint ett_mswsp_property_restriction_val = -1;
static gint ett_CRestrictionArray = -1;
static gint ett_CBaseStorageVariant = -1;
static gint ett_CBaseStorageVariant_Vector = -1;
static gint ett_CBaseStorageVariant_Array = -1;
static gint ett_CDbColId = -1;
static gint ett_GUID = -1;

struct {
    guint propset_array;
    guint propset;
    guint prop;
    guint prop_colid;
    guint prop_value;
    guint prop_value_val;
} ett_idx;

static int parse_padding(tvbuff_t *tvb, int offset, int alignment, proto_tree *pad_tree, const char *text)
{
    if (offset % alignment) {
        const int padding = alignment - (offset % alignment);
        proto_tree_add_text(pad_tree, tvb, offset, padding, "%s (%d)", text ? text : "???", padding);
        offset += padding;
    }
    DISSECTOR_ASSERT((offset % alignment) == 0);
    return offset;
}

static int parse_guid(tvbuff_t *tvb, int offset, proto_tree *tree, e_guid_t *guid, const char *text)
{
    const char *guid_str, *name, *bytes;
    proto_tree *tr;
    proto_item *ti;

    tvb_get_letohguid(tvb, offset, guid);
    guid_str =  guid_to_str(guid);
    name = guids_get_guid_name(guid);

    ti = proto_tree_add_text(tree, tvb, offset, 16, "%s: %s {%s}", text, name ? name : "", guid_str);
    tr = proto_item_add_subtree(ti, ett_GUID);

    proto_tree_add_text(tr, tvb, offset, 4, "time-low: 0x%08x", guid->data1);
    offset += 4;
    proto_tree_add_text(tr, tvb, offset, 2, "time-mid: 0x%04x", guid->data2);
    offset += 2;
    proto_tree_add_text(tr, tvb, offset, 2, "time-high-and-version: 0x%04x", guid->data3);
    offset += 2;
    proto_tree_add_text(tr, tvb, offset, 1, "clock_seq_hi_and_reserved: 0x%02x", guid->data4[0]);
    offset += 1;
    proto_tree_add_text(tr, tvb, offset, 1, "clock_seq_low: 0x%02x", guid->data4[1]);
    offset += 1;
    bytes = bytestring_to_str(&guid->data4[2], 6, ':');
    proto_tree_add_text(tr, tvb, offset, 6, "node: %s", bytes);
    offset += 6;

    return offset;
}

/*****************************************************************************************/
static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                                  struct CNodeRestriction *v);
static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                                     struct CBaseStorageVariant *value, const char *text);



static int parse_CFullPropSpec(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                               struct CFullPropSpec *v)
{
    static const value_string KIND[] = {
        {0, "PRSPEC_LPWSTR"},
        {1, "PRSPEC_PROPID"},
        {0, NULL}
    };
    const char *guid_str;
    proto_item *tree_item = proto_tree_get_parent(tree);

    offset = parse_padding(tvb, offset, 8, pad_tree, "paddingPropSet");

    offset = parse_guid(tvb, offset, tree, &v->guid, "GUID");
    guid_str =  guids_resolve_guid_to_str(&v->guid );
    proto_item_append_text(tree_item, " {%s}", guid_str);

    v->kind = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "ulKind: %s ", val_to_str(v->kind, KIND, "(Unknown: 0x%x)"));
    offset += 4;

    v->u.propid = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "propid: %u ", v->u.propid);
    offset += 4;

    if (v->kind == PRSPEC_LPWSTR) {
        int len = v->u.propid;
        v->u.name = tvb_get_unicode_string(tvb, offset, len, ENC_LITTLE_ENDIAN);
        proto_tree_add_text(tree, tvb, offset, len, "name: \"%s\"", v->u.name);
        proto_item_append_text(tree_item, " \"%s\"", v->u.name);
        offset += len;
    } else if (v->kind == PRSPEC_PROPID) {
        proto_item_append_text(tree_item, " 0x%08x", v->u.propid);
    } else {
        proto_item_append_text(tree_item, "<INVALID>");
    }
    return offset;
}



static int parse_CPropertyRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                                      struct CPropertyRestriction *v)
{
    proto_tree *tr;
    proto_item *ti;

    v->relop = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "relop: 0x%04x", v->relop);
    offset += 4;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "Property");
    tr = proto_item_add_subtree(ti, ett_mswsp_property_restriction);
    offset = parse_CFullPropSpec(tvb, offset, tr, pad_tree, &v->property);
    proto_item_set_end(ti, tvb, offset);

    offset = parse_CBaseStorageVariant(tvb, offset, tr, pad_tree, &v->prval, "prval");

    offset = parse_padding(tvb, offset, 4, pad_tree, "padding_lcid");

    v->lcid = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "lcid: 0x%08x", v->lcid);
    offset += 4;

    return offset;
}

static int parse_CRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                              struct CRestriction *v)
{
    proto_tree *tr;
    proto_item *ti;
    int len;

    v->ulType = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "ulType: 0x%.8x", v->ulType);
    offset += 4;

    v->Weight = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "Weight: %u", v->ulType);
    offset += 4;

    ti = proto_tree_add_text(tree, tvb, offset, 0, "Restriction");
    tr = proto_item_add_subtree(ti, ett_mswsp_restriction);
    switch(v->ulType) {
    case RTNone:
        len = 0;
        break;
    case RTAnd:
    case RTOr:
    case RTProximity:
    case RTPhrase:
    {
        v->u.RTAnd = ep_alloc(sizeof(struct CNodeRestriction)); //XXX
        offset = parse_CNodeRestriction(tvb, offset, tr, pad_tree, v->u.RTAnd);
    }
    break;
    case RTNot:
    {
        v->u.RTNot = ep_alloc(sizeof(struct CRestriction)); //XXX
        offset = parse_CRestriction(tvb, offset, tr, pad_tree, v->u.RTNot);
    }
    case RTProperty:
    {
        v->u.RTProperty = ep_alloc(sizeof(struct CPropertyRestriction)); //XXX
        offset = parse_CPropertyRestriction(tvb, offset, tr, pad_tree, v->u.RTProperty);
    }
    break;
    default:
        proto_item_append_text(ti, " Not supported!");
    }
    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                                  struct CNodeRestriction *v)
{
    proto_item *ti;
    unsigned i;

    v->cNode = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "cNode: %u", v->cNode);
    offset += 4;
    for (i=0; i<v->cNode; i++) {
        struct CRestriction r;
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "paNode[%u]", i);
        proto_tree *tr = proto_item_add_subtree(ti, ett_mswsp_restriction_node);
        ZERO_STRUCT(r);
        offset = parse_CRestriction(tvb, offset, tr, pad_tree, &r);
        proto_item_set_end(ti, tvb, offset);

        offset = parse_padding(tvb, offset, 4, pad_tree, "paNode"); /*at begin or end of loop ????*/
    }
    return offset;
}


/*****************************************************************************************/

static int vvalue_tvb_get0(tvbuff_t *tvb _U_, int offset _U_, void *val _U_)
{
    return 0;
}

static int vvalue_tvb_get1(tvbuff_t *tvb, int offset, void *val)
{
    guint8 *ui1 = (guint8*)val;
    *ui1 = tvb_get_guint8(tvb, offset);
    return 1;
}

static int vvalue_tvb_get2(tvbuff_t *tvb , int offset, void *val)
{
    guint16 *ui2 = (guint16*)val;
    *ui2 = tvb_get_letohs(tvb, offset);
    return 2;
}

static int vvalue_tvb_get4(tvbuff_t *tvb , int offset, void *val)
{
    guint32 *ui4 = (guint32*)val;
    *ui4 = tvb_get_letohl(tvb, offset);
    return 4;
}

static int vvalue_tvb_get8(tvbuff_t *tvb , int offset, void *val)
{
    guint64 *ui8 = (guint64*)val;
    *ui8 = tvb_get_letoh64(tvb, offset);
    return 8;
}

static int vvalue_tvb_blob(tvbuff_t *tvb , int offset, void *val)
{
    struct data_blob *blob = (struct data_blob*)val;
    guint32 len = tvb_get_letohl(tvb, offset);
    const guint8 *data = tvb_get_ptr(tvb, offset + 4, len);

    blob->size = len;
    blob->data = se_memdup(data, len);

    return 4 + len;
}

static int vvalue_tvb_bstr(tvbuff_t *tvb , int offset, void *val)
{
    struct data_str *str = (struct data_str*)val;
    guint32 len = tvb_get_letohl(tvb, offset);
    const void *ptr = tvb_get_ptr(tvb, offset + 4, len);

//XXX this might be UTF-16
    str->len = len;
    str->str = se_strndup(ptr, len);
    return 4 + len;
}

static int vvalue_tvb_lpstr(tvbuff_t *tvb , int offset, void *val)
{
    struct data_str *str = (struct data_str*)val;
    gint len;

    str->len = tvb_get_letohl(tvb, offset);
    str->str = tvb_get_seasonal_stringz(tvb, offset + 4, &len);
    /* XXX test str->len == len */
    return 4 + len;
}

static int vvalue_tvb_lpwstr(tvbuff_t *tvb , int offset, void *val)
{
    struct data_str *str = (struct data_str*)val;
    gint len;
    gchar *ptr;

    str->len = tvb_get_letohl(tvb, offset);

    ptr = tvb_get_ephemeral_unicode_stringz(tvb, offset + 4, &len, ENC_LITTLE_ENDIAN);
    str->str = se_strdup (ptr);

    return 4 + len;
}

static int vvalue_tvb_vector_internal(tvbuff_t *tvb , int offset, struct vt_vector *val, struct vtype *type, int num)
{
    const int offset_in = offset;
    const gboolean varsize = (type->size == -1);
    const int elsize = varsize ? (int)sizeof(struct data_blob) : type->size;
    guint8 *data = se_alloc(elsize * num);
    int len, i;

    val->len = num;
    val->u.vt_ui1 = data;
    DISSECTOR_ASSERT((void*)&val->u == ((void*)&val->u.vt_ui1));

    for (i=0; i<num; i++) {
        len = type->tvb_get(tvb, offset, data);
        data += elsize;
        offset += len;
        if (varsize && (offset % 4) ) { /* at begin or end of loop ??? */
            int padding = 4 - (offset % 4);
            offset += padding;
        }
    }
    return offset - offset_in;
}

static int vvalue_tvb_vector(tvbuff_t *tvb , int offset, struct vt_vector *val, struct vtype *type)
{
    const int num = tvb_get_letohl(tvb, offset);
    return 4 + vvalue_tvb_vector_internal(tvb , offset+4, val, type, num);
}

static void vvalue_strbuf_append_null(emem_strbuf_t *strbuf _U_, void *ptr _U_)
{}

static void vvalue_strbuf_append_i1(emem_strbuf_t *strbuf, void *ptr)
{
    gint8 i1 = *(gint8*)ptr;
    ep_strbuf_append_printf(strbuf, "%d", (int)i1);
}

static void vvalue_strbuf_append_i2(emem_strbuf_t *strbuf, void *ptr)
{
    gint16 i2 = *(gint16*)ptr;
    ep_strbuf_append_printf(strbuf, "%d", (int)i2);
}

static void vvalue_strbuf_append_i4(emem_strbuf_t *strbuf, void *ptr)
{
    gint32 i4 = *(gint32*)ptr;
    ep_strbuf_append_printf(strbuf, "%d", i4);
}

static void vvalue_strbuf_append_i8(emem_strbuf_t *strbuf, void *ptr)
{
    gint64 i8 = *(gint64*)ptr;
    ep_strbuf_append_printf(strbuf, "%ld", i8);
}

static void vvalue_strbuf_append_ui1(emem_strbuf_t *strbuf, void *ptr)
{
    guint8 ui1 = *(guint8*)ptr;
    ep_strbuf_append_printf(strbuf, "%u", (unsigned)ui1);
}

static void vvalue_strbuf_append_ui2(emem_strbuf_t *strbuf, void *ptr)
{
    guint16 ui2 = *(guint16*)ptr;
    ep_strbuf_append_printf(strbuf, "%u", (unsigned)ui2);
}

static void vvalue_strbuf_append_ui4(emem_strbuf_t *strbuf, void *ptr)
{
    guint32 ui4 = *(guint32*)ptr;
    ep_strbuf_append_printf(strbuf, "%d", ui4);
}

static void vvalue_strbuf_append_ui8(emem_strbuf_t *strbuf, void *ptr)
{
    guint64 ui8 = *(guint64*)ptr;
    ep_strbuf_append_printf(strbuf, "%lu", ui8);
}

static void vvalue_strbuf_append_r4(emem_strbuf_t *strbuf, void *ptr)
{
    float r4 = *(float*)ptr;
    ep_strbuf_append_printf(strbuf, "%g", (double)r4);
}

static void vvalue_strbuf_append_r8(emem_strbuf_t *strbuf, void *ptr)
{
    double r8 = *(double*)ptr;
    ep_strbuf_append_printf(strbuf, "%g", r8);
}

static void vvalue_strbuf_append_str(emem_strbuf_t *strbuf, void *ptr)
{
    struct data_str *str = (struct data_str*)ptr;
    ep_strbuf_append_printf(strbuf, "\"%s\"", str->str);
}

static void vvalue_strbuf_append_blob(emem_strbuf_t *strbuf, void *ptr)
{
    struct data_blob *blob = (struct data_blob*)ptr;
    ep_strbuf_append_printf(strbuf, "size: %d", (int)blob->size);
}

static void vvalue_strbuf_append_bool(emem_strbuf_t *strbuf, void *ptr)
{
    guint16 val = *(guint*)ptr;
    switch (val) {
    case 0:
        ep_strbuf_append(strbuf, "False");
        break;
    case 0xffff:
        ep_strbuf_append(strbuf, "True");
        break;
    default:
        ep_strbuf_append_printf(strbuf, "Invalid (0x%4x)", val);
    }
}

static void vvalue_strbuf_append_vector(emem_strbuf_t *strbuf, struct vt_vector val, struct vtype *type)
{
    const int elsize = (type->size == -1) ? (int)sizeof(struct data_blob) : type->size;
    unsigned i;
    guint8 *data = val.u.vt_ui1;
    ep_strbuf_append_c(strbuf, '[');
    for (i=0; i<val.len; i++) {
        if (i>0) {
            ep_strbuf_append_c(strbuf, ',');
        }
        type->strbuf_append(strbuf, data);
        data += elsize;
    }
    ep_strbuf_append_c(strbuf, ']');
}


struct vtype VT_TYPE[] = {
    {VT_EMPTY,             "VT_EMPTY",              0, vvalue_tvb_get0, vvalue_strbuf_append_null},
    {VT_NULL,              "VT_NULL",               0, vvalue_tvb_get0, vvalue_strbuf_append_null},
    {VT_I2,                "VT_I2",                 2, vvalue_tvb_get2, vvalue_strbuf_append_i2},
    {VT_I4,                "VT_I4",                 4, vvalue_tvb_get4, vvalue_strbuf_append_i4},
    {VT_R4,                "VT_R4",                 4, vvalue_tvb_get4, vvalue_strbuf_append_r4},
    {VT_R8,                "VT_R8",                 8, vvalue_tvb_get8, vvalue_strbuf_append_r8},
    {VT_CY,                "VT_CY",                 8, vvalue_tvb_get8, vvalue_strbuf_append_i8},
    {VT_DATE,              "VT_DATE",               8, vvalue_tvb_get8, vvalue_strbuf_append_r8},
//    {VT_BSTR,              "VT_BSTR",              -1, vvalue_tvb_bstr, vvalue_strbuf_append_str},
    {VT_BSTR,              "VT_BSTR",              -1, vvalue_tvb_lpwstr, vvalue_strbuf_append_str},
    {VT_ERROR,             "VT_ERROR",              8, vvalue_tvb_get4, vvalue_strbuf_append_ui4},
    {VT_BOOL,              "VT_BOOL",               2, vvalue_tvb_get2, vvalue_strbuf_append_bool},
    {VT_VARIANT,           "VT_VARIANT",           -1, NULL, NULL},
    {VT_DECIMAL,           "VT_DECIMAL",           16, NULL, NULL},
    {VT_I1,                "VT_I1",                 1, vvalue_tvb_get1, vvalue_strbuf_append_i1},
    {VT_UI1,               "VT_UI1",                1, vvalue_tvb_get1, vvalue_strbuf_append_ui1},
    {VT_UI2,               "VT_UI2",                2, vvalue_tvb_get2, vvalue_strbuf_append_ui2},
    {VT_UI4,               "VT_UI4",                4, vvalue_tvb_get4, vvalue_strbuf_append_ui4},
    {VT_I8,                "VT_I8",                 8, vvalue_tvb_get8, vvalue_strbuf_append_i8},
    {VT_UI8,               "VT_UI8",                8, vvalue_tvb_get8, vvalue_strbuf_append_ui8},
    {VT_INT,               "VT_INT",                4, vvalue_tvb_get4, vvalue_strbuf_append_i4},
    {VT_UINT,              "VT_UINT",               4, vvalue_tvb_get4, vvalue_strbuf_append_ui4},
    {VT_LPSTR,             "VT_LPSTR",             -1, vvalue_tvb_lpstr, vvalue_strbuf_append_str},
    {VT_LPWSTR,            "VT_LPWSTR",            -1, vvalue_tvb_lpwstr, vvalue_strbuf_append_str},
    {VT_COMPRESSED_LPWSTR, "VT_COMPRESSED_LPWSTR", -1, NULL, vvalue_strbuf_append_str},
    {VT_FILETIME,          "VT_FILETIME",           8, vvalue_tvb_get8, vvalue_strbuf_append_i8},
    {VT_BLOB,              "VT_BLOB",              -1, vvalue_tvb_blob, vvalue_strbuf_append_blob},
    {VT_BLOB_OBJECT,       "VT_BLOB_OBJECT",       -1, vvalue_tvb_blob, vvalue_strbuf_append_blob},
    {VT_CLSID,             "VT_CLSID",             16, NULL, NULL},
};

static struct vtype *vType_get_type(enum vType t) {
    unsigned i;
    t &= 0xFF;
    for (i=0; i<array_length(VT_TYPE); i++) {
        if (t == VT_TYPE[i].tag) {
            return &VT_TYPE[i];
        }
    }
    return NULL;
}

static char *str_CBaseStorageVariant(struct CBaseStorageVariant *value, gboolean print_type)
{

    emem_strbuf_t *strbuf = ep_strbuf_new(NULL);
    if (value == NULL) {
        return "<NULL>";
    }

    if (value->type == NULL) {
        return "<??""?>";
    }

    if (print_type) {
        ep_strbuf_append(strbuf, value->type->str);

        if (value->vType & 0xFF00) {
            ep_strbuf_append_printf(strbuf, "[%d]", value->vValue.vt_vector.len);
        }
        ep_strbuf_append(strbuf, ": ");
    }

    switch (value->vType & 0xFF00) {
    case 0:
        value->type->strbuf_append(strbuf, &value->vValue);
        break;
    case VT_ARRAY:
        vvalue_strbuf_append_vector(strbuf, value->vValue.vt_array.vData, value->type);
        break;
    case VT_VECTOR:
        vvalue_strbuf_append_vector(strbuf, value->vValue.vt_vector, value->type);
        break;
    default:
        ep_strbuf_append(strbuf, "Invalid");
    }

    return strbuf->str;
}

static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree _U_,
                                     struct CBaseStorageVariant *value, const char *text)
{
    int i, len;
    proto_item *ti, *ti_type;
    proto_tree *tree, *tr;
    enum vType baseType, highType;

    ZERO_STRUCT(*value);

    ti = proto_tree_add_text(parent_tree, tvb, offset, 0, "%s", text);
    tree = proto_item_add_subtree(ti, ett_CBaseStorageVariant);

    value->vType = tvb_get_letohs(tvb, offset);
    value->type = vType_get_type(value->vType);

    ti_type = proto_tree_add_text(tree, tvb, offset, 2, "vType: %s", value->type->str);
    offset += 2;

    value->vData1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "vData1: %d", value->vData1);
    offset += 1;

    value->vData2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "vData2: %d", value->vData2);
    offset += 1;

    baseType = value->vType & 0x00FF;
    highType = value->vType & 0xFF00;

    if (value->type == NULL) {
        goto not_supported;
    }

    ti = proto_tree_add_text(tree, tvb, offset, 0, "vValue");

    switch (highType) {
    case VT_EMPTY:
        len = value->type->tvb_get(tvb, offset, &value->vValue.vt_single);
        offset += len;
        break;
    case VT_VECTOR:
        proto_item_append_text(ti_type, "|VT_VECTOR");
        tr = proto_item_add_subtree(ti, ett_CBaseStorageVariant_Vector);

        len = vvalue_tvb_vector(tvb, offset, &value->vValue.vt_vector, value->type);
        proto_tree_add_text(tr, tvb, offset, 4, "num: %d", value->vValue.vt_vector.len);
        offset += len;
        break;
    case VT_ARRAY: {
        guint16 cDims, fFeatures;
        guint32 cbElements, cElements, lLbound;
        int num = 1;

        proto_item_append_text(ti_type, "|VT_ARRAY");
        tr = proto_item_add_subtree(ti, ett_CBaseStorageVariant_Array);

        cDims = tvb_get_letohs(tvb, offset);
        proto_tree_add_text(tr, tvb, offset, 2, "cDims: %d", cDims);
        offset += 2;

        fFeatures = tvb_get_letohs(tvb, offset);
        proto_tree_add_text(tr, tvb, offset, 2, "fFeaturess: %d", fFeatures);
        offset += 2;

        cbElements = tvb_get_letohl(tvb, offset);
        proto_tree_add_text(tr, tvb, offset, 4, "cbElements: %d", cbElements);
        offset += 4;
        for (i=0; i<cDims; i++) {
            cElements = tvb_get_letohl(tvb, offset);
            lLbound =  tvb_get_letohl(tvb, offset + 4);
            proto_tree_add_text(tr, tvb, offset, 8, "Rgsabound[%d]: (%d:%d)", i, cElements, lLbound);
            offset += 8;
            num *= cElements;
        }

        len = vvalue_tvb_vector_internal(tvb , offset, &value->vValue.vt_array.vData, value->type, num);
        offset += len;
        break;
    }
    default:
        proto_item_append_text(ti_type, "|0x%x", highType);
    }
    proto_item_set_end(ti, tvb, offset);

    proto_item_append_text(ti, " %s", str_CBaseStorageVariant(value, false));

    goto done;

not_supported:
        proto_item_append_text(ti, ": sorry, vType %02x not handled yet!", (unsigned)value->vType);
done:
    return offset;
}

enum {
    DBKIND_GUID_NAME = 0,
    DBKIND_GUID_PROPID = 1
};

static int parse_CDbColId(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree, const char *text)
{
    int len;
    guint32 eKind, ulId;
    e_guid_t guid;
    static const char *KIND[] = {"DBKIND_GUID_NAME", "DBKIND_GUID_PROPID"};

    proto_item *tree_item = proto_tree_add_text(parent_tree, tvb, offset, 0, "%s", text);
    proto_tree *tree = proto_item_add_subtree(tree_item, ett_CDbColId);

    eKind = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "eKind: %s (%u)", eKind < 2 ? KIND[eKind] : "???", eKind);
    offset += 4;

    offset = parse_padding(tvb, offset, 8, pad_tree, "paddingGuidAlign");

    offset = parse_guid(tvb, offset, tree, &guid, "GUID");

    ulId = tvb_get_letohl(tvb, offset);
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

    proto_item_set_end(tree_item, tvb, offset);

    return offset;
}

static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree)
{
    guint32 id, opt, status;
    struct CBaseStorageVariant value;
    proto_item *tree_item = proto_tree_get_parent(tree);
    char *str;

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

    offset = parse_CDbColId(tvb, offset, tree, pad_tree, "colid");

    offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &value, "vValue");

    str = str_CBaseStorageVariant(&value, true);
    proto_item_append_text(tree_item, " %s", str);

    return offset;
}

static struct {
    e_guid_t guid;
    const char *def;
    const char *desc;
} GuidPropertySet[] = {
    {{0xa9bd1526, 0x6a80, 0x11d0, {0x8c, 0x9d, 0x00, 0x20, 0xaf, 0x1d, 0x74, 0x0e}},
     "DBPROPSET_FSCIFRMWRK_EXT", "File system content index framework"},
    {{0xa7ac77ed, 0xf8d7, 0x11ce, {0xa7, 0x98, 0x00, 0x20, 0xf8, 0x00, 0x80, 0x25}},
     "DBPROPSET_QUERYEXT", "Query extension"},
    {{0xafafaca5, 0xb5d1, 0x11d0, {0x8c, 0x62, 0x00, 0xc0, 0x4f, 0xc2, 0xdb, 0x8d}},
     "DBPROPSET_CIFRMWRKCORE_EXT", "Content index framework core"},
};


static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree)
{
    int i, num;
    e_guid_t guid;
    proto_item *tree_item = proto_tree_get_parent(tree);

    offset = parse_guid(tvb, offset, tree, &guid, "guidPropertySet");

    for (i=0; (unsigned)i<array_length(GuidPropertySet); i++) {
        if (guid_cmp(&GuidPropertySet[i].guid, &guid) == 0) {
            proto_item_append_text(tree_item, " %s (%s)",
                                   GuidPropertySet[i].def,
                                   GuidPropertySet[i].desc);
            break;
        }
    }
    if (i==array_length(GuidPropertySet)) {
        const char *guid_str = guid_to_str(&guid);
        proto_item_append_text(tree_item, " {%s}", guid_str);
    }

    offset = parse_padding(tvb, offset, 4, pad_tree, "guidPropertySet");

    num = tvb_get_letoh24(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cProperties: %d", num);
    offset += 4;
    proto_item_append_text(tree_item, " Size: %d", num);

    for (i = 0; i<num; i++) {
        proto_item *ti;
        proto_tree *tr;

        offset = parse_padding(tvb, offset, 4, pad_tree, "aProp");

        ti = proto_tree_add_text(tree, tvb, offset, 0, "aProp[%d]", i);
        tr = proto_item_add_subtree(ti, ett_mswsp_prop[ett_idx.prop++]); //???
        DISSECTOR_ASSERT(ett_idx.prop <= array_length(ett_mswsp_prop));
        offset = parse_CDbProp(tvb, offset, tr, pad_tree);
        proto_item_set_end(ti, tvb, offset);
    }
    return offset;
}

static int parse_PropertySetArray(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree, int size_offset)
{
    const int offset_in = offset;
    guint32 size, num;
    int i;

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
        offset = parse_CDbPropSet(tvb, offset, tr, pad_tree);
        proto_item_set_end(ti, tvb, offset);
    }

    DISSECTOR_ASSERT(offset - offset_in == (int)size);
    return offset;
}

/* Code to actually dissect the packets */

static int dissect_CPMConnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in)
{
    proto_item *ti;
    proto_tree *tree;
    gint offset = 16;
    guint len;
    guint32 version;

    ZERO_STRUCT(ett_idx);

    ti = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mswsp_msg);
    proto_item_set_text(ti, "CPMConnect%s", in ? "In" : "Out");
    col_append_str(pinfo->cinfo, COL_INFO, "Connect");

    version = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_item(tree, hf_mswsp_msg_Connect_Version, tvb,
                             offset, 4, ENC_LITTLE_ENDIAN);
    if (version & 0xffff0000) {
        proto_item_append_text(ti, " 64 bit");
    }
    switch (version & 0xffff) {
    case 0x102:
        proto_item_append_text(ti, " w2k8 or vista");
        break;
    case 0x109:
        proto_item_append_text(ti, " XP or w2k3, with Windows Search 4.0");
        break;
    case 0x700:
        proto_item_append_text(ti, " win7 or w2k8r2");
        break;
    }
    offset += 4;

    if (in) {
        guint32 blob_size1_off, blob_size2_off;
        proto_tree *pad_tree, *tr;

        ti = proto_tree_add_text(tree, tvb, offset, 0, "Padding");
        pad_tree = proto_item_add_subtree(ti, ett_mswsp_pad);

        proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_ClientIsRemote, tvb,
                            offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* _cbBlob1 */
        blob_size1_off = offset;
        offset += 4;

        offset = parse_padding(tvb, offset, 8, pad_tree, "_paddingcbBlob2");

        /* _cbBlob2 */
        blob_size2_off = offset;
        offset += 4;

        offset = parse_padding(tvb, offset, 16, pad_tree, "_padding");

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

        offset = parse_padding(tvb, offset, 8, pad_tree, "_paddingcPropSets");

        ti = proto_tree_add_text(tree, tvb, offset, 0, "PropSets");
        tr = proto_item_add_subtree(ti, ett_mswsp_propset_array[0]);
        offset = parse_PropertySetArray(tvb, offset, tr, pad_tree, blob_size1_off);
        proto_item_set_end(ti, tvb, offset);

        offset = parse_padding(tvb, offset, 8, pad_tree, "paddingExtPropset");

        ti = proto_tree_add_text(tree, tvb, offset, 0, "ExtPropset");
        tr = proto_item_add_subtree(ti, ett_mswsp_propset_array[0 /*XXX*/]);
        offset = parse_PropertySetArray(tvb, offset, tr, pad_tree, blob_size2_off);
        proto_item_set_end(ti, tvb, offset);

        offset = parse_padding(tvb, offset, 8, pad_tree, NULL);
        DISSECTOR_ASSERT(offset == (int)tvb_length(tvb));

        /* make "Padding" the last item */
        proto_tree_move_item(tree, ti, proto_tree_get_parent(pad_tree));
    } else {

    }
    return tvb_length(tvb);
}

static int dissect_CPMDisconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, gboolean in _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, "Disconnect");
    return tvb_length(tvb);
}

static int dissect_CPMCreateQuery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, gboolean in)
{
    gint offset = 16;
    proto_item *ti;
    proto_tree *tree;

    ti = proto_tree_add_item(parent_tree, hf_mswsp_msg, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_mswsp_msg);

    proto_item_set_text(ti, "CPMCreateQuery%s", in ? "In" : "Out");
    col_append_str(pinfo->cinfo, COL_INFO, "CreateQuery");

    if (in) {
        proto_item *ti = proto_tree_add_text(tree, tvb, offset, 0, "Padding");
        proto_tree *pad_tree = proto_item_add_subtree(ti, ett_mswsp_pad);
        guint8 CColumnSetPresent, CRestrictionPresent;
        int len;
        guint32 size = tvb_get_letohl(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 4, "size");
        proto_tree_add_text(tree, tvb, offset, size, "ALL");
        offset += 4;

        CColumnSetPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CColumnSetPresent: %s", CColumnSetPresent ? "True" : "False");
        offset += 1;

        if (CColumnSetPresent) {
            guint32 count;
            offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCColumnSetPresent");

            count = tvb_get_letohl(tvb, offset);
            len = 4 + 4*count;
            proto_tree_add_text(tree, tvb, offset, len, "CColumnSet: count %d", count);
            offset += len;
        }

        CRestrictionPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CRestrictionPresent: %s", CColumnSetPresent ? "True" : "False");
        offset += 1;
        if (CRestrictionPresent) {
            guint8 count, present;
            int i;
            count = tvb_get_guint8(tvb, offset);
            present = tvb_get_guint8(tvb, offset);
            ti = proto_tree_add_text(tree, tvb, offset, 0, "CRestrictionSet: count %d", count);
            offset += 2;
            if (present) {
                offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCRestrictionPresent");

                for (i=0; i<count; i++) {
                    struct CRestriction r;
                    proto_item *ti2 = proto_tree_add_text(tree, tvb, offset, 0, "CRestrictionArray[%d]", i);
                    proto_tree *tr2 = proto_item_add_subtree(ti2, ett_CRestrictionArray);

                    offset = parse_CRestriction(tvb, offset, tr2, pad_tree, &r);
                }
            }
            proto_item_set_end(ti, tvb, offset);
        }
    }

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
    static const char *dbg_wait = NULL;
    static int wait_frame = -1;

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

    if (dbg_wait == NULL) {
        dbg_wait = getenv("DBG_FRAME");
        if (dbg_wait == NULL) {
            dbg_wait = "no";
        } else {
            wait_frame = atoi(dbg_wait);
        }
    }

    if ((int)pinfo->fd->num == wait_frame) {
        static volatile gboolean wait = 1;
        while(wait) {
            sleep(1);
        }
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
		{ &hf_mswsp_msg_Connect_Version,
                  { "Version", "mswsp.Connect.version",
                    FT_UINT32, BASE_HEX , NULL, 0,
                    "Version",HFILL }
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
            &ett_mswsp_restriction,
            &ett_mswsp_restriction_node,
            &ett_mswsp_property_restriction,
            &ett_mswsp_property_restriction_val,
            &ett_CRestrictionArray,
            &ett_CBaseStorageVariant,
            &ett_CBaseStorageVariant_Vector,
            &ett_CBaseStorageVariant_Array,
            &ett_CDbColId,
            &ett_GUID,
	};

        int i;

/* Register the protocol name and description */
	proto_mswsp = proto_register_protocol("Windows Search Protocol",
                                              "MS-WSP", "mswsp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mswsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
        register_ett_array(ett_mswsp_propset_array, array_length(ett_mswsp_propset_array));
        register_ett_array(ett_mswsp_propset, array_length(ett_mswsp_propset));
        register_ett_array(ett_mswsp_prop, array_length(ett_mswsp_prop));

        for (i=0; i<(int)array_length(GuidPropertySet); i++) {
            guids_add_guid(&GuidPropertySet[i].guid, GuidPropertySet[i].def);
        }

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
