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

#include <sys/types.h>
#include <unistd.h>


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

static gint ett_mswsp_property_restriction = -1;
static gint ett_CRestrictionArray = -1;
static gint ett_CBaseStorageVariant = -1;
static gint ett_CBaseStorageVariant_Vector = -1;
static gint ett_CBaseStorageVariant_Array = -1;
static gint ett_CDbColId = -1;
static gint ett_GUID = -1;
static gint ett_CDbProp = -1;
static gint ett_CDbPropSet = -1;
static gint ett_CDbPropSet_Array = -1;
static gint ett_CRestriction = -1;
static gint ett_CNodeRestriction = -1;
static gint ett_CPropertyRestriction = -1;
static gint ett_CCoercionRestriction = -1;
static gint ett_CContentRestriction = -1;
static gint ett_RANGEBOUNDARY = -1;
static gint ett_CRangeCategSpec = -1;
static gint ett_CCategSpec = -1;
static gint ett_CAggregSpec = -1;
static gint ett_CAggregSet = -1;
static gint ett_CCategorizationSpec = -1;
static gint ett_CAggregSortKey = -1;
static gint ett_CSortAggregSet = -1;
static gint ett_CInGroupSortAggregSet = -1;
static gint ett_CInGroupSortAggregSets = -1;
static gint ett_CRowsetProperties = -1;
static gint ett_CFullPropSpec = -1;
static gint ett_CPidMapper = -1;
static gint ett_CSort = -1;
static gint ett_CSortSet = -1;
static gint ett_CNatLanguageRestriction = -1;
static gint ett_CColumnGroup = -1;
static gint ett_CColumnGroupArray = -1;
static gint ett_LCID = -1;

/******************************************************************************/
struct GuidPropertySet {
    e_guid_t guid;
    const char *def;
    const char *desc;
    const value_string *id_map;
};

/* 2.2.1.31.1 */
static const value_string DBPROPSET_FSCIFRMWRK_EXT_IDS[] = {
    {0x02, "DBPROP_CI_CATALOG_NAME"},
    {0x03, "DBPROP_CI_INCLUDE_SCOPES"},
    {0x04, "DBPROP_CI_SCOPE_FLAGS"},
    {0x07, "DBPROP_CI_QUERY_TYPE"},
    {0, NULL}
};

static const value_string DBPROPSET_QUERYEXT_IDS[] = {
    {0x02, "DBPROP_USECONTENTINDEX"},
    {0x03, "DBPROP_DEFERNONINDEXEDTRIMMING"},
    {0x04, "DBPROP_USEEXTENDEDDBTYPES"},
    {0x05, "DBPROP_IGNORENOISEONLYCLAUSES"},
    {0x06, "DBPROP_GENERICOPTIONS_STRING"},
    {0x07, "DBPROP_FIRSTROWS"},
    {0x08, "DBPROP_DEFERCATALOGVERIFICATION"},
    {0x0a, "DBPROP_GENERATEPARSETREE"},
    {0x0c, "DBPROP_FREETEXTANYTERM"},
    {0x0d, "DBPROP_FREETEXTUSESTEMMING"},
    {0x0e, "DBPROP_IGNORESBRI"},
    {0x10, "DBPROP_ENABLEROWSETEVENTS"},
    {0, NULL}
};

static const value_string DBPROPSET_CIFRMWRKCORE_EXT_IDS[] = {
    {0x02, "DBPROP_MACHINE"},
    {0x03, "DBPROP_CLIENT_CLSID"},
    {0, NULL}
};

static const value_string DBPROPSET_MSIDXS_ROWSETEXT_IDS[] = {
    {0x02, "MSIDXSPROP_ROWSETQUERYSTATUS"},
    {0x03, "MSIDXSPROP_COMMAND_LOCALE_STRING"},
    {0x04, "MSIDXSPROP_QUERY_RESTRICTION"},
    {0x05, "MSIDXSPROP_PARSE_TREE"},
    {0x06, "MSIDXSPROP_MAX_RANK"},
    {0x07, "MSIDXSPROP_RESULTS_FOUND"},
    {0, NULL}
};

/* 2.2.5.1 */
static const value_string QueryGuid_IDS[] = {
    {0x02, "RankVector"},
    {0x03, "System.Search.Rank"},
    {0x04, "System.Search.HitCount"},
    {0x05, "System.Search.EntryID"},
    {0x06, "All"},
    {0x09, "System.ItemURL"},
    {0, NULL}
};

/* 2.2.5.2 */
static const value_string StorageGuid_IDS[] = {
    {0x02, "System.ItemFolderNameDisplay"},
    {0x03, "ClassId"},
    {0x04, "System.ItemTypeText"},
    {0x08, "FileIndex"},
    {0x09, "USN"},
    {0x0a, "System.ItemNameDisplay"},
    {0x0b, "Path"},
    {0x0c, "System.Size"},
    {0x0d, "System.FileAttributes"},
    {0x0e, "System.DateModified"},
    {0x0f, "System.DateCreated"},
    {0x10, "System.DateAccessed"},
    {0x12, "AllocSize"},
    {0x13, "System.Search.Contents"},
    {0x14, "ShortFilename"},
    {0x15, "FileFRN"},
    {0x16, "Scope"},
    {0, NULL}
};

static const value_string DocPropSetGuid_IDS[] = {
    {0x02, "System.Title"},
    {0x03, "System.Subject"},
    {0x04, "System.Author"},
    {0x05, "System.Keywords"},
    {0x06, "System.Comment"},
    {0x07, "DocTemplate"},
    {0x08, "System.Document.LastAuthor"},
    {0x09, "System.Document.RevisionNumber"},
    {0x0a, "System.Document.EditTime???"},
    {0x0b, "System.Document.DatePrinted"},
    {0x0c, "System.Document.DateCreated"},
    {0x0d, "System.Document.DateSaved"},
    {0x0e, "System.Document.PageCount"},
    {0x0f, "System.Document.WordCount"},
    {0x10, "System.Document.CharacterCount"},
    {0x11, "DocThumbnail"},
    {0x12, "System.ApplicationName"},
    {0, NULL}
};

static const value_string ShellDetails_IDS[] = {
    { 5, "System.ComputerName"},
    { 8, "System.ItemPathDisplayNarrow"},
    { 9, "PercivedType"},
    {11, "System.ItemType"},
    {12, "FileCount"},
    {14, "TotalFileSize"},
    {24, "System.ParsingName"},
    {25, "System.SFGAOFlags"},
    {0, NULL}
};

static const value_string PropSet1_IDS[] = {
    {100, "System.ThumbnailCacheId"},
    {0, NULL}
};

static const value_string PropSet2_IDS[] = {
    {3, "System.Kind"},
    {0, NULL}
};

static const value_string MusicGuid_IDS[] = {
    {0, NULL}
};

static const value_string PropSet3_IDS[] = {
    { 2, "System.Message.BccAddress"},
    { 3, "System.Message.BccName"},
    { 4, "System.Message.CcAddress"},
    { 5, "System.Message.CcName"},
    { 6, "System.ItemFolderPathDisplay"},
    { 7, "System.ItemPathDisplay"},
    { 9, "System.Communication.AccountName"},
    {10, "System.IsRead"},
    {11, "System.Importance"},
    {12, "System.FlagStatus"},
    {13, "System.Message.FromAddress"},
    {14, "System.Message.FromName"},
    {15, "System.Message.Store"},
    {16, "System.Message.ToAddress"},
    {17, "System.Message.ToName"},
    {18, "System.Contact.WebPage"},
    {19, "System.Message.DateSent"},
    {20, "System.Message.DateReceived"},
    {21, "System.Message.AttachmentNames"},
    {0, NULL}
};

static const value_string PropSet4_IDS[] = {
    {100, "System.ItemFolderPathDisplayNarrow"},
    {0, NULL}
};

static const value_string PropSet5_IDS[] = {
    {100, "System.Contact.FullName"},
    {0, NULL}
};

static const value_string PropSet6_IDS[] = {
    {100, "System.ItemAuthors"},
    {0, NULL}
};

static const value_string PropSet7_IDS[] = {
    {2, "System.Shell.OmitFromView"},
    {0, NULL}
};

static const value_string PropSet8_IDS[] = {
    {2, "System.Shell.SFGAOFlagsStrings"},
    {3, "System.Link.TargetSFGAOFlagsStrings"},
    {0, NULL}
};

static struct GuidPropertySet GuidPropertySet[] = {
    {{0xa9bd1526, 0x6a80, 0x11d0, {0x8c, 0x9d, 0x00, 0x20, 0xaf, 0x1d, 0x74, 0x0e}},
     "DBPROPSET_FSCIFRMWRK_EXT", "File system content index framework",
     DBPROPSET_FSCIFRMWRK_EXT_IDS},
    {{0xa7ac77ed, 0xf8d7, 0x11ce, {0xa7, 0x98, 0x00, 0x20, 0xf8, 0x00, 0x80, 0x25}},
     "DBPROPSET_QUERYEXT", "Query extension",
     DBPROPSET_QUERYEXT_IDS},
    {{0xafafaca5, 0xb5d1, 0x11d0, {0x8c, 0x62, 0x00, 0xc0, 0x4f, 0xc2, 0xdb, 0x8d}},
     "DBPROPSET_CIFRMWRKCORE_EXT", "Content index framework core",
     DBPROPSET_CIFRMWRKCORE_EXT_IDS},
    {{0xAA6EE6B0, 0xE828, 0x11D0, {0xB2, 0x3E, 0x00, 0xAA, 0x00, 0x47, 0xFC, 0x01}},
      "DBPROPSET_MSIDXS_ROWSETEXT", "???",
     DBPROPSET_MSIDXS_ROWSETEXT_IDS},
    {{0xB725F130, 0x47ef, 0x101a, {0xA5, 0xF1, 0x02, 0x60, 0x8C, 0x9E, 0xEB, 0xAC}},
     "Storage", "Storage Property Set",
     StorageGuid_IDS},
    {{0xF29F85E0, 0x4FF9, 0x1068, {0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9}},
      "Document", "Document Property Set",
      DocPropSetGuid_IDS},
    {{0x49691C90, 0x7E17, 0x101A, {0xA9, 0x1C, 0x08, 0x00, 0x2B, 0x2E, 0xCD, 0xA9}},
     "Query", "Query Property Set",
     QueryGuid_IDS},
    {{0x28636AA6, 0x953D, 0x11D2, {0xB5, 0xD6, 0x00, 0xC0, 0x4F, 0xD9, 0x18, 0xD0}},
     "ShellDetails", "Shell Details Property Set",
    ShellDetails_IDS},
    {{0x446D16B1, 0x8DAD, 0x4870, {0xA7, 0x48, 0x40, 0x2E, 0xA4, 0x3D, 0x78, 0x8C}},
     "???", "Unspecified Property Set",
     PropSet1_IDS},
    {{0x1E3EE840, 0xBC2B, 0x476C, {0x82, 0x37, 0x2A, 0xCD, 0x1A, 0x83, 0x9B, 0x22}},
     "???", "Unspecified Property Set",
     PropSet2_IDS},
    {{0x56A3372E, 0xCE9C, 0x11d2, {0x9F, 0x0E, 0x00, 0x60, 0x97, 0xC6, 0x86, 0xF6}},
     "Music", "Music Property Set",
     MusicGuid_IDS},
    {{0xE3E0584C, 0xB788, 0x4A5A, {0xBB, 0x20, 0x7F, 0x5A, 0x44, 0xC9, 0xAC, 0xDD}},
     "???", "Unspecified Property Set",
     PropSet3_IDS},
    {{0xDABD30ED, 0x0043, 0x4789, {0xA7, 0xF8, 0xD0, 0x13, 0xA4, 0x73, 0x66, 0x22}},
     "???", "Unspecified Property Set",
     PropSet4_IDS},
    {{0x635E9051, 0x50A5, 0x4BA2, {0xB9, 0xDB, 0x4E, 0xD0, 0x56, 0xC7, 0x72, 0x96}},
     "???", "Unspecified Property Set",
     PropSet5_IDS},
    {{0xD0A04F0A, 0x462A, 0x48A4, {0xBB, 0x2F, 0x37, 0x06, 0xE8, 0x8D, 0xBD, 0x7D}},
     "???", "Unspecified Property Set",
     PropSet6_IDS},
    {{0xDE35258C, 0xC695, 0x4CBC, {0xB9, 0x82, 0x38, 0xB0, 0xAD, 0x24, 0xCE, 0xD0}},
     "???", "Unspecified Property Set",
     PropSet7_IDS},
    {{0xD6942081, 0xD53B, 0x443D, {0xAD, 0x47, 0x5E, 0x05, 0x9D, 0x9C, 0xD2, 0x7A}},
     "???", "Unspecified Property Set",
     PropSet8_IDS},
};

static struct GuidPropertySet *GuidPropertySet_find_guid(const e_guid_t *guid)
{
    unsigned i;
    for (i=0; i<array_length(GuidPropertySet); i++) {
        if (guid_cmp(&GuidPropertySet[i].guid, guid) == 0) {
            return &GuidPropertySet[i];
        }
    }
    return NULL;
}

/******************************************************************************/

static int parse_padding(tvbuff_t *tvb, int offset, int alignment, proto_tree *pad_tree, const char *fmt, ...)
{
    if (offset % alignment) {
        const int padding = alignment - (offset % alignment);
        va_list ap;
        proto_item *ti;
        va_start(ap, fmt);
        ti = proto_tree_add_text_valist(pad_tree, tvb, offset, padding, fmt, ap);
        va_end(ap);

        proto_item_append_text(ti, " (%d)", padding);
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

static const value_string LCID_LID[] = {
    {0x0407, "de-DE"},
    {0x0409, "en-US"},
    {0, NULL}
};


/*Language Code ID: http://msdn.microsoft.com/en-us/library/cc233968(v=prot.20).aspx */
static int parse_lcid(tvbuff_t *tvb, int offset, proto_tree *parent_tree, const char *text)
{
    proto_item *item;
    proto_tree *tree;
    guint32 lcid;
    const char *langid;

    item = proto_tree_add_text(parent_tree, tvb, offset, 4, "%s", text);
    tree = proto_item_add_subtree(item, ett_LCID);

    lcid = tvb_get_letohl(tvb, offset);
    langid = val_to_str(lcid & 0xFFFF, LCID_LID, "0x%04x");
    proto_tree_add_text(tree, tvb, offset+2, 2, "Language ID: %s", langid);
    proto_item_append_text(item, ": %s", langid);
    proto_tree_add_text(tree, tvb, offset+1,1, "Sort ID: %u", (lcid >> 16) & 0xf);
    offset += 4;
    return offset;
}

/*****************************************************************************************/
/* 2.2.1.1 CBaseStorageVariant */
static int parse_CBaseStorageVariant(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                                     struct CBaseStorageVariant *value, const char *text);

/* 2.2.1.2 CFullPropSpec */
static int parse_CFullPropSpec(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                               struct CFullPropSpec *v, const char *fmt, ...);

/* 2.2.1.3 CContentRestriction */
static int parse_CContentRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                     proto_tree *pad_tree, struct CContentRestriction *v,
                                     const char *fmt, ...);

/* 2.2.1.5 CNatLanguageRestriction */
static int parse_CNatLanguageRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                         proto_tree *pad_tree, struct CNatLanguageRestriction *v,
                                         const char *fmt, ...);

/* 2.2.1.6 CNodeRestriction */
static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *tree, proto_tree *pad_tree,
                                  struct CNodeRestriction *v, const char* fmt, ...);

/* 2.2.1.7 CPropertyRestriction */
static int parse_CPropertyRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                      proto_tree *pad_tree, struct CPropertyRestriction *v,
                                      const char *fmt, ...);

/* 2.2.1.8 CReuseWhere */
static int parse_CReuseWhere(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                             proto_tree *pad_tree _U_, struct CReuseWhere *v,
                             const char *fmt, ...);

/* 2.2.1.10 CSort */
static int parse_CSort(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                       proto_tree *pad_tree _U_,
                       const char *fmt, ...);

/* 2.2.1.12 CCoercionRestriction */
static int parse_CCoercionRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                      proto_tree *pad_tree, struct CCoercionRestriction *v,
                                      const char *fmt, ...);
/* 2.2.1.16 CRestrictionArray */
static int parse_CRestrictionArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                                   const char *fmt, ...);

/* 2.2.1.17 CRestriction */
static int parse_CRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                              struct CRestriction *v, const char *fmt, ...);

/* 2.2.1.18 CColumnSet */
static int parse_CColumnSet(tvbuff_t *tvb, int offset, proto_tree *tree, const char *fmt, ...);

/* 2.2.1.20 CCategorizationSpec */
static int parse_CCategorizationSpec(tvbuff_t *tvb, int offset,
                                     proto_tree *parent_tree, proto_tree *pad_tree,
                                     const char *fmt, ...);

/* 2.2.1.21 CCategSpec */
static int parse_CCategSpec(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree,
                            const char *fmt, ...);

/* 2.2.1.22 CRangeCategSpec */
static int parse_CRangeCategSpec(tvbuff_t *tvb, int offset,
                                 proto_tree *parent_tree, proto_tree *pad_tree,
                                 const char *fmt, ...);

/* 2.2.1.23 RANGEBOUNDARY */
static int parse_RANGEBOUNDARY(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                               proto_tree *pad_tree, const char *fmt, ...);

/* 2.2.1.24 CAggregSet */
static int parse_CAggregSet(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree,
                            const char *fmt, ...);

/* 2.2.1.25 CAggregSpec */
static int parse_CAggregSpec(tvbuff_t *tvb, int offset,
                             proto_tree *parent_tree, proto_tree *pad_tree,
                             const char *fmt, ...);

/* 2.2.1.26 CSortAggregSet */
static int parse_CSortAggregSet(tvbuff_t *tvb, int offset,
                                proto_tree *parent_tree, proto_tree *pad_tree,
                                const char *fmt, ...);

/* 2.2.1.27 CAggregSortKey */
static int parse_CAggregSortKey(tvbuff_t *tvb, int offset,
                                proto_tree *parent_tree, proto_tree *pad_tree,
                                const char *fmt, ...);

/* 2.2.1.28 CInGroupSortAggregSets */
static int parse_CInGroupSortAggregSets(tvbuff_t *tvb, int offset,
                                        proto_tree *parent_tree, proto_tree *pad_tree,
                                        const char *fmt, ...);

/* 2.2.1.29 CInGroupSortAggregSet */
static int parse_CInGroupSortAggregSet(tvbuff_t *tvb, int offset,
                                       proto_tree *parent_tree, proto_tree *pad_tree,
                                       const char *fmt, ...);
/* 2.2.1.30 CDbColId */
static int parse_CDbColId(tvbuff_t *tvb, int offset,
                          proto_tree *parent_tree, proto_tree *pad_tree, const char *text);

/* 2.2.1.31 CDbProp */
static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                         proto_tree *pad_tree, struct GuidPropertySet *propset,
                         const char *fmt, ...);

/* 2.2.1.32 CDbPropSet */
static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                            proto_tree *pad_tree, const char *fmt, ...);
/* 2.2.1.33 CPidMapper */
static int parse_CPidMapper(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree,
                            const char *fmt, ...);

/* 2.2.1.34 CColumnGroupArray */
static int parse_CColumnGroupArray(tvbuff_t *tvb, int offset,
                                   proto_tree *parent_tree, proto_tree *pad_tree,
                                   const char *fmt, ...);

/* 2.2.1.35 CColumnGroup */
static int parse_CColumnGroup(tvbuff_t *tvb, int offset,
                              proto_tree *parent_tree, proto_tree *pad_tree,
                              const char *fmt, ...);

/* 2.2.1.41 CRowsetProperties */
static int parse_CRowsetProperties(tvbuff_t *tvb, int offset,
                                   proto_tree *parent_tree, proto_tree *pad_tree,
                                   const char *fmt, ...);

/* 2.2.1.43 CSortSet */
static int parse_CSortSet(tvbuff_t *tvb, int offset,
                          proto_tree *parent_tree, proto_tree *pad_tree,
                          const char *fmt, ...);

/*
2.2.1.4 CInternalPropertyRestriction
2.2.1.9 CScopeRestriction
2.2.1.11 CVectorRestriction
2.2.1.13 CRelDocRestriction
2.2.1.14 CProbRestriction
2.2.1.15 CFeedbackRestriction
2.2.1.19 CCategorizationSet
2.2.1.37 CRowSeekAt
2.2.1.38 CRowSeekAtRatio
2.2.1.39 CRowSeekByBookmark
2.2.1.40 CRowSeekNext
2.2.1.42 CRowVariant
2.2.1.44 CTableColumn
2.2.1.45 SERIALIZEDPROPERTYVALUE
2.2.1.46 CCompletionCategSp
*/

static int parse_CSort(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                       proto_tree *pad_tree _U_,
                       const char *fmt, ...)
{
    guint32 col, ord, ind;

    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CSort);

    col = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "column: %u", col);
    offset += 4;

    ord = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "order: %u", ord);
    offset += 4;

    ind = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "individual: %u", ind);
    offset += 4;

    offset = parse_lcid(tvb, offset, tree, "lcid");

    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int parse_CSortSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                          proto_tree *pad_tree,
                          const char *fmt, ...)
{
    guint32 count, i;

    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CSortSet);

    count = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", count);
    offset += 4;

    for (i=0; i<count; i++) {
        offset = parse_padding(tvb, offset, 4, tree, "padding_sortArray[%u]", i);
        offset = parse_CSort(tvb, offset, tree, pad_tree, "sortArray[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}


static int parse_CFullPropSpec(tvbuff_t *tvb, int offset,
                               proto_tree *parent_tree, proto_tree *pad_tree,
                               struct CFullPropSpec *v, const char *fmt, ...)
{
    static const value_string KIND[] = {
        {0, "PRSPEC_LPWSTR"},
        {1, "PRSPEC_PROPID"},
        {0, NULL}
    };

    struct GuidPropertySet *pset;
    const char *id_str, *guid_str;

    proto_item *item;
    proto_tree *tree;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CFullPropSpec);

    offset = parse_padding(tvb, offset, 8, pad_tree, "paddingPropSet");

    offset = parse_guid(tvb, offset, tree, &v->guid, "GUID");
    pset = GuidPropertySet_find_guid(&v->guid);

    v->kind = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "ulKind: %s ", val_to_str(v->kind, KIND, "(Unknown: 0x%x)"));
    offset += 4;

    v->u.propid = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "propid: %u ", v->u.propid);
    offset += 4;

    if (v->kind == PRSPEC_LPWSTR) {
        int len = 2*v->u.propid;
        v->u.name = tvb_get_unicode_string(tvb, offset, len, ENC_LITTLE_ENDIAN);
        proto_tree_add_text(tree, tvb, offset, len, "name: \"%s\"", v->u.name);
        offset += len;
    }

    id_str = pset ? match_strval(v->u.propid, pset->id_map) : NULL;

    if (id_str) {
        proto_item_append_text(item, ": %s", id_str);
    } else {
        guid_str = guids_get_guid_name(&v->guid);
        if (guid_str) {
            proto_item_append_text(item, ": \"%s\"", guid_str);
        } else {
            guid_str = guid_to_str(&v->guid);
            proto_item_append_text(item, ": {%s}", guid_str);
        }

        if (v->kind == PRSPEC_LPWSTR) {
            proto_item_append_text(item, " \"%s\"", v->u.name);
        } else if (v->kind == PRSPEC_PROPID) {
            proto_item_append_text(item, " 0x%08x", v->u.propid);
        } else {
            proto_item_append_text(item, " <INVALID>");
        }
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}



static const value_string PR_VALS[] = {
	{PRLT, "PRLT"},
	{PRLE, "PRLE"},
	{PRGT, "PRGT"},
	{PRGE, "PRGE"},
	{PREQ, "PREQ"},
	{PRNE, "PRNE"},
	{PRRE, "PRRE"},
	{PRAllBits, "PRAllBits"},
	{PRSomeBits, "PRSomeBits"},
	{PRAll, "PRAll"},
	{PRSome, "PRSome"},
};


static int parse_CPropertyRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                      proto_tree *pad_tree, struct CPropertyRestriction *v,
                                      const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    const char *str;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CPropertyRestriction);

    v->relop = tvb_get_letohl(tvb, offset);
    str = val_to_str(v->relop, PR_VALS, "0x%04x");
    proto_tree_add_text(tree, tvb, offset, 4, "relop: %s (0x%04x)",
                        str[0]=='\0' ? "" : str, v->relop);
    proto_item_append_text(item, " Op: %s", str);
    offset += 4;

    offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

    offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &v->prval, "prval");

    offset = parse_padding(tvb, offset, 4, pad_tree, "padding_lcid");

    v->lcid = tvb_get_letohl(tvb, offset);
    offset = parse_lcid(tvb, offset, tree, "lcid");

    proto_item_set_end(item, tvb, offset);

    return offset;
}

static int parse_CCoercionRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                      proto_tree *pad_tree, struct CCoercionRestriction *v,
                                      const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CCoercionRestriction);

    v->value = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "value: %g", (double)v->value);
    offset += 4;

    offset = parse_CRestriction(tvb, offset, tree, pad_tree, &v->child, "child");

    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int parse_CContentRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                     proto_tree *pad_tree, struct CContentRestriction *v,
                                     const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    va_list ap;
    guint32 cc;
    const char *str;


    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CContentRestriction);

    offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

    offset = parse_padding(tvb, offset, 4, pad_tree, "Padding1");

    cc = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cc: %u", cc);
    offset += 4;

//    str = tvb_get_ephemeral_string_enc(tvb, offset, 2*cc, ENC_UTF_16);
    str = tvb_get_unicode_string(tvb, offset, 2*cc, ENC_LITTLE_ENDIAN);
    v->phrase = se_strdup(str);
    proto_tree_add_text(tree, tvb, offset, 2*cc, "phrase: %s", str);
    offset += 2*cc;

    offset = parse_padding(tvb, offset, 4, pad_tree, "Padding2");

    v->lcid = tvb_get_letohl(tvb, offset);
    offset = parse_lcid(tvb, offset, tree, "lcid");

    v->method = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "method: 0x%08x", v->method);
    offset += 4;

    proto_item_set_end(item, tvb, offset);
    return offset;
}

int parse_CNatLanguageRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                         proto_tree *pad_tree, struct CNatLanguageRestriction *v,
                                         const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    va_list ap;
    guint32 cc;
    const char *str;


    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CNatLanguageRestriction);

    offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v->property, "Property");

    offset = parse_padding(tvb, offset, 4, pad_tree, "padding_cc");

    cc = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cc: %u", cc);
    offset += 4;

//    str = tvb_get_ephemeral_string_enc(tvb, offset, 2*cc, ENC_UTF_16);
    str = tvb_get_unicode_string(tvb, offset, 2*cc, ENC_LITTLE_ENDIAN);
    v->phrase = se_strdup(str);
    proto_tree_add_text(tree, tvb, offset, 2*cc, "phrase: %s", str);
    offset += 2*cc;

    offset = parse_padding(tvb, offset, 4, pad_tree, "padding_lcid");

    v->lcid = tvb_get_letohl(tvb, offset);
    offset = parse_lcid(tvb, offset, tree, "lcid");

    proto_item_set_end(item, tvb, offset);
    return offset;
}


static int parse_CReuseWhere(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                             proto_tree *pad_tree _U_, struct CReuseWhere *v,
                             const char *fmt, ...)
{
    proto_item *item;
    va_list ap;


    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    v->whereId = tvb_get_letohl(tvb, offset);
    offset += 4;

    proto_item_append_text(item, " Id: %u", v->whereId);

    proto_item_set_end(item, tvb, offset);
    return offset;
};

static value_string RT_VALS[] =  {
    {RTNone, "RTNone"},
    {RTAnd, "RTAnd"},
    {RTOr, "RTOr"},
    {RTNot, "RTNot"},
    {RTContent, "RTContent"},
    {RTProperty, "RTProperty"},
    {RTProximity, "RTProximity"},
    {RTVector, ""},
    {RTNatLanguage, "RTNatLanguage"},
    {RTScope, "RTScope"},
    {RTCoerce_Add, "RTCoerce_Add"},
    {RTCoerce_Multiply, "RTCoerce_Multiply"},
    {RTCoerce_Absolute, "RTCoerce_Absolute"},
    {RTProb, "RTProb"},
    {RTFeedback, "RTFeedback"},
    {RTReldoc, "RTReldoc"},
    {RTReuseWhere, "RTReuseWhere"},
    {RTInternalProp, "RTInternalProp"},
    {RTPhrase, "RTInternalProp"},
};

static int parse_CRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                              struct CRestriction *v, const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    const char *str;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CRestriction);


    v->ulType = tvb_get_letohl(tvb, offset);
    str = val_to_str(v->ulType, RT_VALS, "0x%.8x");
    proto_tree_add_text(tree, tvb, offset, 4, "ulType: %s (0x%.8x)",
                             str[0] == '0' ? "" : str, v->ulType);
    proto_item_append_text(item, " Type: %s", str);
    offset += 4;

    v->Weight = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Weight: %u", v->ulType);
    offset += 4;

    switch(v->ulType) {
    case RTNone:
        break;
    case RTAnd:
    case RTOr:
    case RTProximity:
    case RTPhrase:
    {
        v->u.RTAnd = ep_alloc(sizeof(struct CNodeRestriction)); //XXX
        offset = parse_CNodeRestriction(tvb, offset, tree, pad_tree, v->u.RTAnd, "CNodeRestriction");
        break;
    }
    case RTNot:
    {
        v->u.RTNot = ep_alloc(sizeof(struct CRestriction)); //XXX
        offset = parse_CRestriction(tvb, offset, tree, pad_tree,
                                    v->u.RTNot, "CRestriction");
        break;
    }
    case RTProperty:
    {
        v->u.RTProperty = ep_alloc(sizeof(struct CPropertyRestriction)); //XXX
        offset = parse_CPropertyRestriction(tvb, offset, tree, pad_tree,
                                            v->u.RTProperty, "CPropertyRestriction");
        break;
    }
    case RTCoerce_Add:
    case RTCoerce_Multiply:
    case RTCoerce_Absolute:
    {
        v->u.RTCoerce_Add = ep_alloc(sizeof(struct CCoercionRestriction)); //XXX
        offset = parse_CCoercionRestriction(tvb, offset, tree, pad_tree,
                                            v->u.RTCoerce_Add, "CCoercionRestriction");
        break;
    }
    case RTContent: {
        v->u.RTContent = ep_alloc(sizeof(struct CContentRestriction)); //XXX
        offset = parse_CContentRestriction(tvb, offset, tree, pad_tree,
                                           v->u.RTContent, "CContentRestriction");
        break;
    }
    case RTReuseWhere: {
        v->u.RTReuseWhere = ep_alloc(sizeof(struct CReuseWhere)); //XXX
        offset = parse_CReuseWhere(tvb, offset, tree, pad_tree,
                                   v->u.RTReuseWhere, "CReuseWhere");
        break;
    }
    case RTNatLanguage: {
        v->u.RTNatLanguage = ep_alloc(sizeof(struct CNatLanguageRestriction)); //XXX
        offset = parse_CNatLanguageRestriction(tvb, offset, tree, pad_tree,
                                   v->u.RTNatLanguage, "CNatLanguageRestriction");
        break;
    }
    default:
        fprintf(stderr, "CRestriciont 0x%08x not Supported\n", v->ulType);
        proto_item_append_text(item, " Not supported!");
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int parse_CRestrictionArray(tvbuff_t *tvb, int offset, proto_tree *parent_tree, proto_tree *pad_tree,
                                   const char *fmt, ...)
{
    guint8 present, count;

    proto_tree *tree;
    proto_item *item;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CRestrictionArray);

    pad_tree = tree; //XXX

    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "count: %u", count);
    offset += 1;

    present = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "present: %u", present);
    offset += 1;

    if (present) {
        unsigned i;
        offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCRestrictionPresent");

        for (i=0; i<count; i++) {
            struct CRestriction r;
            offset = parse_CRestriction(tvb, offset, tree, pad_tree, &r, "Restriction[%d]", i);
        }
    }
    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int parse_CNodeRestriction(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                                  proto_tree *pad_tree, struct CNodeRestriction *v,
                                  const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    unsigned i;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CNodeRestriction);

    v->cNode = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cNode: %u", v->cNode);
    offset += 4;

    for (i=0; i<v->cNode; i++) {
        struct CRestriction r;
        ZERO_STRUCT(r);
//        offset = parse_padding(tvb, offset, 4, tree, "padding_paNode[%u]", i); /*at begin or end of loop ????*/
        offset = parse_CRestriction(tvb, offset, tree, pad_tree, &r, "paNode[%u]", i);
        offset = parse_padding(tvb, offset, 4, tree, "padding_paNode[%u]", i); /*at begin or end of loop ????*/

//        offset = parse_padding(tvb, offset, 4, pad_tree, "paNode[%u]", i); /*at begin or end of loop ????*/
    }

    proto_item_set_end(item, tvb, offset);
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


static struct vtype VT_TYPE[] = {
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
    proto_item *ti, *ti_type, *ti_val;
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

    ti_val = proto_tree_add_text(tree, tvb, offset, 0, "vValue");

    switch (highType) {
    case VT_EMPTY:
        len = value->type->tvb_get(tvb, offset, &value->vValue.vt_single);
        offset += len;
        break;
    case VT_VECTOR:
        proto_item_append_text(ti_type, "|VT_VECTOR");
        tr = proto_item_add_subtree(ti_val, ett_CBaseStorageVariant_Vector);

        len = vvalue_tvb_vector(tvb, offset, &value->vValue.vt_vector, value->type);
        proto_tree_add_text(tr, tvb, offset, 4, "num: %d", value->vValue.vt_vector.len);
        offset += len;
        break;
    case VT_ARRAY: {
        guint16 cDims, fFeatures;
        guint32 cbElements, cElements, lLbound;
        int num = 1;

        proto_item_append_text(ti_type, "|VT_ARRAY");
        tr = proto_item_add_subtree(ti_val, ett_CBaseStorageVariant_Array);

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
    proto_item_set_end(ti_val, tvb, offset);

    proto_item_append_text(ti_val, " %s", str_CBaseStorageVariant(value, false));
    proto_item_append_text(ti, " %s", str_CBaseStorageVariant(value, true));

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
        int len = ulId; //*2 ???
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

static int parse_CDbProp(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                         proto_tree *pad_tree, struct GuidPropertySet *propset,
                         const char *fmt, ...)
{
    static const value_string EMPTY_VS[] = {{0, NULL}};
    const value_string *vs = (propset && propset->id_map) ? propset->id_map : EMPTY_VS;
    guint32 id, opt, status;
    struct CBaseStorageVariant value;
    proto_item *item;
    proto_tree *tree;
    const char *str;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CDbProp);

    id = tvb_get_letohl(tvb, offset);
    str = val_to_str(id, vs, "0x%08x");
    proto_tree_add_text(tree, tvb, offset, 4, "Id: %s (0x%08x)", str[0] == '0' ? "" : str, id);
    offset += 4;
    proto_item_append_text(item, " Id: %s", str);

    opt = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Options: %08x", opt);
    offset += 4;

    status = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Status: %08x", status);
    offset += 4;

    offset = parse_CDbColId(tvb, offset, tree, pad_tree, "colid");

    offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &value, "vValue");

    str = str_CBaseStorageVariant(&value, true);
    proto_item_append_text(item, " %s", str);
    proto_item_set_end(item, tvb, offset);

    return offset;
}

static int parse_CDbPropSet(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                            proto_tree *pad_tree, const char *fmt, ...)
{
    int i, num;
    e_guid_t guid;
    struct GuidPropertySet *pset;
    proto_item *item;
    proto_tree *tree;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CDbPropSet);

    offset = parse_guid(tvb, offset, tree, &guid, "guidPropertySet");

    pset = GuidPropertySet_find_guid(&guid);

    if (pset) {
        proto_item_append_text(item, " \"%s\" (%s)", pset->desc, pset->def);
    } else {
        const char *guid_str = guid_to_str(&guid);
        proto_item_append_text(item, " {%s}", guid_str);
    }

    offset = parse_padding(tvb, offset, 4, pad_tree, "guidPropertySet");

    num = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cProperties: %d", num);
    offset += 4;
    proto_item_append_text(item, " Num: %d", num);

    for (i = 0; i<num; i++) {
        offset = parse_padding(tvb, offset, 4, pad_tree, "aProp[%d]", i);
        offset = parse_CDbProp(tvb, offset, tree, pad_tree, pset, "aProp[%d]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

static int parse_PropertySetArray(tvbuff_t *tvb, int offset, int size_offset,
                                  proto_tree *parent_tree, proto_tree *pad_tree,
                                  const char *fmt, ...)
{
    const int offset_in = offset;
    guint32 size, num;
    int i;
    proto_tree *tree;
    proto_item *item;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    tree = proto_item_add_subtree(item, ett_CDbPropSet_Array);

    size = tvb_get_letohl(tvb, size_offset);
    proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_Blob1, tvb,
                        size_offset, 4, ENC_LITTLE_ENDIAN);

    num = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_mswsp_msg_ConnectIn_PropSets_num, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    for (i = 0; i < (int)num; i++) {
        offset = parse_CDbPropSet(tvb, offset, tree, pad_tree, "PropertySet[%d]", i);
    }

    proto_item_set_end(item, tvb, offset);
    DISSECTOR_ASSERT(offset - offset_in == (int)size);
    return offset;
}

int parse_CColumnSet(tvbuff_t *tvb, int offset, proto_tree *tree, const char *fmt, ...)
{
    guint32 count, v, i;
    proto_item *item;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(tree, tvb, offset, 0, fmt, ap);
    va_end(ap);

    count = tvb_get_letohl(tvb, offset);
    offset += 4;

    proto_item_append_text(item, " Count %u [", count);
    for (i=0; i<count; i++) {
        v = tvb_get_letohl(tvb, offset);
        offset += 4;
        if (i>0) {
            proto_item_append_text(item, ",%u", v);
        } else {
            proto_item_append_text(item, "%u", v);
        }
    }
    proto_item_append_text(item, "]");
    return offset;
}

/* 2.2.1.23 RANGEBOUNDARY */
int parse_RANGEBOUNDARY(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                        proto_tree *pad_tree, const char *fmt, ...)
{
    guint32 ulType;
    guint8 labelPresent;
    proto_item *item;
    proto_tree *tree;
    struct CBaseStorageVariant prval;
    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_RANGEBOUNDARY);
    va_end(ap);

    ulType = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "ulType 0x%08x", ulType);
    proto_item_append_text(item, ": Type 0x%08x", ulType);
    offset += 4;

    ZERO_STRUCT(prval);
    offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &prval, "prVal");

    labelPresent = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "labelPresent: %s", labelPresent ? "True" : "False");
    offset += 1;

    if (labelPresent) {
        guint32 ccLabel;
        const char *label;
        offset = parse_padding(tvb, offset, 4, pad_tree, "paddingLabelPresent");

        ccLabel = tvb_get_letohl(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 4, "ccLabel: %u", ccLabel);
        offset += 4;

        label = tvb_get_unicode_string(tvb, offset, 2*ccLabel, ENC_LITTLE_ENDIAN);
        proto_tree_add_text(tree, tvb, offset, 2*ccLabel, "Label: \"%s\"", label);
        proto_item_append_text(item, " Label: \"%s\"", label);
        offset += 2*ccLabel;
    }

    proto_item_append_text(item, " Val: %s", str_CBaseStorageVariant(&prval, true));

    proto_item_set_end(item, tvb, offset);
    return offset;
}


/* 2.2.1.22 CRangeCategSpec */
int parse_CRangeCategSpec(tvbuff_t *tvb, int offset,
                          proto_tree *parent_tree, proto_tree *pad_tree,
                          const char *fmt, ...)
{
    proto_item *item;
    proto_tree *tree;
    va_list ap;
    unsigned i;
    guint32 cRange;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CRangeCategSpec);
    va_end(ap);

    offset = parse_lcid(tvb, offset, tree, "lcid");

    cRange = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cRange 0x%08x", cRange);
    offset += 4;

    for (i=0; i<cRange; i++) {
        offset = parse_RANGEBOUNDARY(tvb, offset, tree, pad_tree, "aRangeBegin[%u]", i);

    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.21 CCategSpec */
int parse_CCategSpec(tvbuff_t *tvb, int offset,
                     proto_tree *parent_tree, proto_tree *pad_tree,
                     const char *fmt, ...)
{
    proto_item *item;
    proto_tree *tree;

    va_list ap;
    guint32 type;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CCategSpec);
    va_end(ap);

    type = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "Type 0x%08x", type);
    proto_item_append_text(item, " Type %u", type);
    offset += 4;

    offset = parse_CSort(tvb, offset, tree, pad_tree, "CSort");

    offset = parse_CRangeCategSpec(tvb, offset, tree, pad_tree, "CRangeCategSpec");

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.25 CAggregSpec */
static int parse_CAggregSpec(tvbuff_t *tvb, int offset,
                             proto_tree *parent_tree, proto_tree *pad_tree,
                             const char *fmt, ...)
{
    proto_item *item;
    proto_tree *tree;
    va_list ap;
    guint8 type;
    guint32 ccAlias, idColumn, ulMaxNumToReturn, idRepresentative;
    const char *alias;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CAggregSpec);
    va_end(ap);

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "type: %u", type);
    proto_item_append_text(item, "type: %u", type);
    offset += 1;

    offset = parse_padding(tvb, offset, 4, pad_tree, "padding");

    ccAlias = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "ccAlias: %u", ccAlias);
    offset += 4;

    alias = tvb_get_unicode_string(tvb, offset, 2*ccAlias, ENC_LITTLE_ENDIAN);
    proto_tree_add_text(tree, tvb, offset, 2*ccAlias, "Alias: %s", alias);
    offset += 2*ccAlias;

    idColumn = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "idColumn: %u", idColumn);
    offset += 4;
    /* Optional ???
       ulMaxNumToReturn, idRepresentative;
    */
    fprintf(stderr, "WARNING, dont know if optional members are present!\n ");

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.24 CAggregSet */
static int parse_CAggregSet(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree,
                            const char *fmt, ...)
{
    guint32 cCount, i;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CAggregSet);
    va_end(ap);

    cCount = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", cCount);
    offset += 4;

    for (i=0; i<cCount; i++) {
        /* 2.2.1.25 CAggregSpec */
        offset = parse_CAggregSpec(tvb, offset, tree, pad_tree, "AggregSpecs[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.27 CAggregSortKey */
static int parse_CAggregSortKey(tvbuff_t *tvb, int offset,
                                proto_tree *parent_tree, proto_tree *pad_tree,
                                const char *fmt, ...)
{
    guint32 order;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CAggregSortKey);
    va_end(ap);

    order = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "order: %u", order);
    offset += 4;

    offset = parse_CAggregSpec(tvb, offset, tree, pad_tree, "ColumnSpec");

    proto_item_set_end(item, tvb, offset);
    return offset;
}


/* 2.2.1.26 CSortAggregSet */
static int parse_CSortAggregSet(tvbuff_t *tvb, int offset,
                                proto_tree *parent_tree, proto_tree *pad_tree,
                                const char *fmt, ...)
{
    guint32 cCount, i;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CSortAggregSet);
    va_end(ap);

    cCount = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", cCount);
    offset += 4;

    for (i=0; i<cCount; i++) {
        /* 2.2.1.27 CAggregSortKey */
        offset = parse_CAggregSortKey(tvb, offset, tree, pad_tree, "SortKeys[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

enum CInGroupSortAggregSet_type {
    GroupIdDefault = 0x00, /* The default for all ranges. */
    GroupIdMinValue = 0x01, /*The first range in the parent's group.*/
    GroupIdNull = 0x02, /*The last range in the parent's group.*/
    GroupIdValue = 0x03,
};

/* 2.2.1.29 CInGroupSortAggregSet */
static int parse_CInGroupSortAggregSet(tvbuff_t *tvb, int offset,
                                       proto_tree *parent_tree, proto_tree *pad_tree,
                                       const char *fmt, ...)
{
    proto_item *item;
    proto_tree *tree;
    va_list ap;
    enum CInGroupSortAggregSet_type type;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CInGroupSortAggregSet);
    va_end(ap);

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1, "Type: 0x%02x", (unsigned)type);
    offset += 1;

    offset = parse_padding(tvb, offset, 4, pad_tree, "CInGroupSortAggregSet");

    if (type == GroupIdValue) {
        struct CBaseStorageVariant id;
        offset = parse_CBaseStorageVariant(tvb, offset, tree, pad_tree, &id, "inGroupId");
    }

    offset = parse_CSortAggregSet(tvb, offset, tree, pad_tree, "SortAggregSet");

    proto_item_set_end(item, tvb, offset);
    return offset;
}


/* 2.2.1.28 CInGroupSortAggregSets */
static int parse_CInGroupSortAggregSets(tvbuff_t *tvb, int offset,
                                        proto_tree *parent_tree, proto_tree *pad_tree,
                                        const char *fmt, ...)
{
    guint32 cCount, i;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CInGroupSortAggregSets);
    va_end(ap);

    cCount = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", cCount);
    offset += 4;

    for (i=0; i<cCount; i++) {
        /* 2.2.1.29 CInGroupSortAggregSet */
        offset = parse_CInGroupSortAggregSet(tvb, offset, tree, pad_tree, "SortSets[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.20 CCategorizationSpec */
int parse_CCategorizationSpec(tvbuff_t *tvb, int offset,
                              proto_tree *parent_tree, proto_tree *pad_tree,
                              const char *fmt, ...)
{
    guint32 cMaxResults;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CCategorizationSpec);
    va_end(ap);

    /* 2.2.1.18  CColumnSet */
    offset = parse_CColumnSet(tvb, offset, tree, "csColumns");

    /* 2.2.1.21 CCategSpec */
    offset = parse_CCategSpec(tvb, offset, tree, pad_tree, "Spec");

    /* 2.2.1.24 CAggregSet */
    offset = parse_CAggregSet(tvb, offset, tree, pad_tree, "AggregSet");

    /* 2.2.1.26 CSortAggregSet */
    offset = parse_CSortAggregSet(tvb, offset, tree, pad_tree, "SortAggregSet");

    /* 2.2.1.28 CInGroupSortAggregSets */
    offset = parse_CInGroupSortAggregSets(tvb, offset, tree, pad_tree, "InGroupSortAggregSets");

    cMaxResults = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cMaxResults: %u", cMaxResults);
    offset += 4;

    proto_item_set_end(item, tvb, offset);
    return offset;
}

int parse_CRowsetProperties(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree _U_,
                            const char *fmt, ...)
{
    guint32 opt, maxres, timeout;
    proto_item *item;
    proto_tree *tree;

    va_list ap;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CRowsetProperties);
    va_end(ap);

    opt = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "uBooleanOptions: 0x%08x", opt);
    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "ulMaxOpenRows (ignored)");
    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "ulMemoryUsage (ignored)");
    offset += 4;

    maxres = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cMaxResults: %u", maxres);
    offset += 4;

    timeout = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "cCmdTimeout: %u", timeout);
    offset += 4;

    proto_item_set_end(item, tvb, offset);
    return offset;
}

int parse_CPidMapper(tvbuff_t *tvb, int offset,
                     proto_tree *parent_tree, proto_tree *pad_tree,
                     const char *fmt, ...)
{
    proto_item *item;
    proto_tree *tree;
    va_list ap;
    guint32 count, i;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    tree = proto_item_add_subtree(item, ett_CPidMapper);
    va_end(ap);

    count = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", count);
    offset += 4;

    offset = parse_padding(tvb, offset, 8, pad_tree, "CPidMapper_PropSpec");

    for (i=0; i<count; i++) {
        struct CFullPropSpec v;
        ZERO_STRUCT(v);
        offset = parse_padding(tvb, offset, 4, pad_tree,
                               "CPidMapper_PropSpec[%u]", i); //at begin or end of loop???
        offset = parse_CFullPropSpec(tvb, offset, tree, pad_tree, &v, "PropSpec[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.35 CColumnGroup */
int parse_CColumnGroup(tvbuff_t *tvb, int offset,
                       proto_tree *parent_tree, proto_tree *pad_tree,
                       const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item, *ti;
    va_list ap;

    guint32 count, groupPid, i;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CColumnGroup);

    count = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", count);
    offset += 4;

    groupPid = tvb_get_letohl(tvb, offset);
    ti = proto_tree_add_text(tree, tvb, offset, 4, "groupPid: 0x%08x", groupPid);
    if ((0xFFFF0000 & groupPid) == 0x7FFF0000) {
        proto_item_append_text(ti, " Idx: %u", groupPid & 0xFFFF);
    } else {
        proto_item_append_text(ti, "<Invalid>");
    }
    offset += 4;

    for (i=0; i<count; i++) {
        /* 2.2.1.36 SProperty */
        guint32 pid, weight;
        pid = tvb_get_letohl(tvb, offset);
        weight = tvb_get_letohl(tvb, offset + 4);
        proto_tree_add_text(tree, tvb, offset, 8, "Props[%u]: pid: %u weight: %u", i, pid, weight);
        offset += 8;
    }

    proto_item_set_end(item, tvb, offset);
    return offset;
}

/* 2.2.1.34 CColumnGroupArray */
int parse_CColumnGroupArray(tvbuff_t *tvb, int offset,
                            proto_tree *parent_tree, proto_tree *pad_tree,
                            const char *fmt, ...)
{
    proto_tree *tree;
    proto_item *item;
    va_list ap;

    guint32 count, i;

    va_start(ap, fmt);
    item = proto_tree_add_text_valist(parent_tree, tvb, offset, 0, fmt, ap);
    va_end(ap);
    tree = proto_item_add_subtree(item, ett_CColumnGroupArray);

    count = tvb_get_letohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "count: %u", count);
    offset += 4;

    for (i=0; i<count; i++) {
        offset = parse_padding(tvb, offset, 4, pad_tree, "aGroupArray[%u]", i);
        offset = parse_CColumnGroup(tvb, offset, tree, pad_tree, "aGroupArray[%u]", i);
    }

    proto_item_set_end(item, tvb, offset);
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
        proto_tree *pad_tree;

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

        offset = parse_PropertySetArray(tvb, offset, blob_size1_off, tree, pad_tree, "PropSets");

        offset = parse_padding(tvb, offset, 8, pad_tree, "paddingExtPropset");

        offset = parse_PropertySetArray(tvb, offset, blob_size2_off, tree, pad_tree, "ExtPropset");

        offset = parse_padding(tvb, offset, 8, pad_tree, "???");

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
        guint8 CColumnSetPresent, CRestrictionPresent, CSortSetPresent, CCategorizationSetPresent;
        guint32 size = tvb_get_letohl(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 4, "size");
        proto_tree_add_text(tree, tvb, offset, size, "ALL");
        offset += 4;

        CColumnSetPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CColumnSetPresent: %s", CColumnSetPresent ? "True" : "False");
        offset += 1;

        if (CColumnSetPresent) {
            offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCColumnSetPresent");
            offset = parse_CColumnSet(tvb, offset, tree, "CColumnSet");
        }

        CRestrictionPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CRestrictionPresent: %s", CColumnSetPresent ? "True" : "False");
        offset += 1;
        if (CRestrictionPresent) {
            offset = parse_CRestrictionArray(tvb, offset, tree, pad_tree, "RestrictionArray");
        }

        CSortSetPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CSortSetPresent: %s", CSortSetPresent ? "True" : "False");
        offset += 1;
        if (CSortSetPresent) {
            offset = parse_padding(tvb, offset, 4, tree, "paddingCSortSetPresent");

            proto_tree_add_text(tree, tvb, offset, 8, "XXX");
            offset += 8;

            offset = parse_CSortSet(tvb, offset, tree, pad_tree, "SortSet");
        }

        CCategorizationSetPresent = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(tree, tvb, offset, 1, "CCategorizationSetPresent: %s", CCategorizationSetPresent ? "True" : "False");
        offset += 1;

        if (CCategorizationSetPresent) {
            guint32 count, i;
            offset = parse_padding(tvb, offset, 4, pad_tree, "paddingCCategorizationSetPresent");
            /* 2.2.1.19 CCategorizationSet */
            count = tvb_get_letohl(tvb, offset);
            proto_tree_add_text(tree, tvb, offset, 4, "count: %u", count);
            offset += 4;
            for (i=0; i<count; i++) {
                offset = parse_CCategorizationSpec(tvb, offset, tree, pad_tree, "categories[%u]", i);
            }
        }

        offset = parse_padding(tvb, offset, 4, tree, "XXXX"); //XXX

        offset = parse_CRowsetProperties(tvb, offset, tree, pad_tree, "RowSetProperties");

        offset = parse_CPidMapper(tvb, offset, tree, pad_tree, "PidMapper");

        offset = parse_CColumnGroupArray(tvb, offset, tree, pad_tree, "GroupArray");
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

static void debug_frame(int frame)
{
    static const char *dbg_wait = NULL;
    static int wait_frame = -1;

    if (dbg_wait == NULL) {
        dbg_wait = getenv("DBG_FRAME");
        if (dbg_wait == NULL) {
            dbg_wait = "no";
        } else {
            wait_frame = atoi(dbg_wait);
        }
    }

    if (frame == wait_frame) {
        static volatile gboolean wait = 1;
        fprintf(stderr, "waiting for debugger with pid: %u\n", getpid());
        while(wait) {
            sleep(1);
        }
    }

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

    hdr.msg = tvb_get_letohl(tvb, 0);

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

    hdr.status = tvb_get_letohl(tvb, 4);
    hdr.checksum = tvb_get_letohl(tvb, 8);

    /* col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS-WSP"); */
    col_append_str(pinfo->cinfo, COL_PROTOCOL, " WSP");
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
            &ett_mswsp_property_restriction,
            &ett_CRestrictionArray,
            &ett_CBaseStorageVariant,
            &ett_CBaseStorageVariant_Vector,
            &ett_CBaseStorageVariant_Array,
            &ett_CDbColId,
            &ett_GUID,
            &ett_CDbProp,
            &ett_CDbPropSet,
            &ett_CDbPropSet_Array,
            &ett_CRestriction,
            &ett_CNodeRestriction,
            &ett_CPropertyRestriction,
            &ett_CCoercionRestriction,
            &ett_CContentRestriction,
            &ett_RANGEBOUNDARY,
            &ett_CRangeCategSpec,
            &ett_CCategSpec,
            &ett_CAggregSpec,
            &ett_CAggregSet,
            &ett_CCategorizationSpec,
            &ett_CAggregSortKey,
            &ett_CSortAggregSet,
            &ett_CInGroupSortAggregSet,
            &ett_CInGroupSortAggregSets,
            &ett_CRowsetProperties,
            &ett_CFullPropSpec,
            &ett_CPidMapper,
            &ett_CSort,
            &ett_CSortSet,
            &ett_CNatLanguageRestriction,
            &ett_CColumnGroup,
            &ett_CColumnGroupArray,
            &ett_LCID,
	};

        int i;

/* Register the protocol name and description */
	proto_mswsp = proto_register_protocol("Windows Search Protocol",
                                              "MS-WSP", "mswsp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mswsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

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

    smb_transact_info_t *tri = (si->sip->extra_info_type == SMB_EI_TRI) ? si->sip->extra_info : NULL;
    smb_fid_info_t *fid_info = NULL;
    GSList *iter;

    debug_frame((int)pinfo->fd->num);

    fprintf(stderr, "dissect_mswsp_smb %s frame: %d tid: %d op: %02x ",
            in ? "Request" : "Response",
            pinfo->fd->num, si->tid, si->cmd);

    if (tri == NULL) {
        fprintf(stderr, " extra_info_type: %d\n", si->sip->extra_info_type);
        return 0;
    }

    for (iter = si->ct->GSL_fid_info; iter; iter = g_slist_next(iter)) {
        smb_fid_info_t *info = iter->data;
        if ((info->tid == si->tid) && (info->fid == tri->fid)) {
            fid_info = info;
            break;
        }
    }

    if (!fid_info || !fid_info->fsi || !fid_info->fsi->filename) {
        fprintf(stderr, " no %s\n", fid_info ? (fid_info->fsi ? "filename" : "fsi") : "fid_info");
        return 0;
    }

    fprintf(stderr, " file: %s\n", fid_info->fsi->filename);

    if (strcasecmp(fid_info->fsi->filename, "\\MsFteWds") != 0) {
        return 0;
    }

    return dissect_mswsp(tvb, pinfo, tree, in);
}


static int dissect_mswsp_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    smb2_info_t *si = pinfo->private_data;
    gboolean in = !(si->flags & SMB2_FLAGS_RESPONSE);

//si->tree->share_type == SMB2_SHARE_TYPE_PIPE
//si->tree->connect_frame

    debug_frame((int)pinfo->fd->num);

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
