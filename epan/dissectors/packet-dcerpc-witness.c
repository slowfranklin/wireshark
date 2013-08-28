/* DO NOT EDIT
	This filter was automatically generated
	from pidl/witness.idl and pidl/witness.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files.
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be
	found at http://wiki.wireshark.org/Pidl
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _MSC_VER
#pragma warning(disable:4005)
#pragma warning(disable:4013)
#pragma warning(disable:4018)
#pragma warning(disable:4101)
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-witness.h"

/* Ett declarations */
static gint ett_witness_move_ipaddr_list_flags = -1;
static gint ett_witness_move_ipaddr = -1;
static gint ett_message_buffer = -1;
static gint ett_dcerpc_witness = -1;
static gint ett_witness_witness_interfaceInfo_flags = -1;
static gint ett_witness_witness_interfaceInfo = -1;
static gint ett_witness_witness_interfaceList = -1;
static gint ett_witness_witness_notifyResponse = -1;


/* Header field declarations */
static gint hf_witness_move_ipaddr_list_flags = -1;
static gint hf_witness_witness_notifyResponse_num_messages = -1;
static gint hf_witness_witness_notifyResponse_message_type = -1;
static gint hf_witness_werror = -1;
static gint hf_witness_witness_Register_version = -1;
static gint hf_witness_witness_Register_client_computer_name = -1;
static gint hf_witness_witness_interfaceList_num_interfaces = -1;
static gint hf_witness_context_handle = -1;
static gint hf_witness_witness_interfaceList_interfaces = -1;
static gint hf_witness_move_ipaddr_list_ipv6 = -1;
static gint hf_witness_witness_AsyncNotify_response = -1;
static gint hf_witness_opnum = -1;
static gint hf_witness_witness_interfaceInfo_version = -1;
static gint hf_witness_change_type = -1;
static gint hf_witness_move_ipaddr_list_flags_ipv4 = -1;
static gint hf_dcerpc_array_max_count = -1;
static gint hf_witness_witness_interfaceInfo_flags_WITNESS_IF = -1;
static gint hf_witness_witness_interfaceInfo_group_name = -1;
static gint hf_witness_witness_interfaceInfo_flags_IPv6_VALID = -1;
static gint hf_witness_move_ipaddr_list_flags_ipv6 = -1;
static gint hf_witness_witness_interfaceInfo_flags_IPv4_VALID = -1;
static gint hf_witness_witness_interfaceInfo_flags = -1;
static gint hf_witness_witness_interfaceInfo_ipv6 = -1;
static gint hf_witness_witness_interfaceInfo_ipv4 = -1;
static gint hf_witness_change_name = -1;
static gint hf_witness_witness_interfaceInfo_state = -1;
static gint hf_witness_witness_notifyResponse_length = -1;
static gint hf_witness_move_ipaddr_list_ipv4 = -1;
static gint hf_witness_witness_notifyResponse_message_buffer = -1;
static gint hf_witness_witness_GetInterfaceList_interface_list = -1;
static gint hf_witness_witness_Register_net_name = -1;
static gint hf_witness_witness_Register_ip_address = -1;

static gint proto_dcerpc_witness = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_witness = {
	0xccd8c074, 0xd0e5, 0x4a40,
	{ 0x92, 0xb4, 0xd0, 0x74, 0xfa, 0xa6, 0xba, 0x28 }
};
static guint16 ver_dcerpc_witness = 1;

const value_string witness_witness_version_vals[] = {
	{ WITNESS_V1, "WITNESS_V1" },
	{ WITNESS_V2, "WITNESS_V2" },
{ 0, NULL }
};
const value_string witness_witness_interfaceInfo_state_vals[] = {
	{ UNKNOWN, "UNKNOWN" },
	{ AVAILABLE, "AVAILABLE" },
	{ UNAVAILABLE, "UNAVAILABLE" },
{ 0, NULL }
};
static const true_false_string witness_interfaceInfo_flags_IPv4_VALID_tfs = {
   "IPv4_VALID is SET",
   "IPv4_VALID is NOT SET",
};
static const true_false_string witness_interfaceInfo_flags_IPv6_VALID_tfs = {
   "IPv6_VALID is SET",
   "IPv6_VALID is NOT SET",
};
static const true_false_string witness_interfaceInfo_flags_WITNESS_IF_tfs = {
   "WITNESS_IF is SET",
   "WITNESS_IF is NOT SET",
};
static int witness_dissect_element_interfaceInfo_group_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_group_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_state(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_ipv4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_ipv6(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceInfo_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceList_num_interfaces(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceList_interfaces(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceList_interfaces_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_interfaceList_interfaces__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
const value_string witness_witness_notifyResponse_type_vals[] = {
	{ RESOURCE_CHANGE, "RESOURCE_CHANGE" },
	{ CLIENT_MOVE, "CLIENT_MOVE" },
	{ SHARE_MOVE, "SHARE_MOVE" },
	{ IP_CHANGE, "IP_CHANGE" },
{ 0, NULL }
};
static int witness_dissect_element_notifyResponse_message_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_notifyResponse_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_notifyResponse_num_messages(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_notifyResponse_message_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_notifyResponse_message_buffer_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_notifyResponse_message_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_GetInterfaceList_interface_list(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_GetInterfaceList_interface_list_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_GetInterfaceList_interface_list__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_context_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_net_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_net_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_ip_address(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_ip_address_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_client_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_Register_client_computer_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_UnRegister_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_AsyncNotify_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_AsyncNotify_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_AsyncNotify_response_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int witness_dissect_element_AsyncNotify_response__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
 #include "packet-dcerpc-witness-cnf.c"


/* IDL: enum { */
/* IDL: 	WITNESS_V1=0x00010001, */
/* IDL: 	WITNESS_V2=0x00020000, */
/* IDL: } */

int
witness_dissect_enum_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint32 parameter=0;
	if(param){
		parameter=(guint32)*param;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: enum { */
/* IDL: 	UNKNOWN=0x00, */
/* IDL: 	AVAILABLE=0x01, */
/* IDL: 	UNAVAILABLE=0xff, */
/* IDL: } */


/* IDL: bitmap { */
/* IDL: 	IPv4_VALID =  0x01 , */
/* IDL: 	IPv6_VALID =  0x02 , */
/* IDL: 	WITNESS_IF =  0x04 , */
/* IDL: } */

int
witness_dissect_bitmap_interfaceInfo_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	guint32 flags;
	ALIGN_TO_4_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item,ett_witness_witness_interfaceInfo_flags);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, NULL, drep, -1, &flags);
	proto_item_append_text(item, ": ");

	if (!flags)
		proto_item_append_text(item, "(No values set)");

	proto_tree_add_boolean(tree, hf_witness_witness_interfaceInfo_flags_IPv4_VALID, tvb, offset-4, 4, flags);
	if (flags&( 0x01 )){
		proto_item_append_text(item, "IPv4_VALID");
		if (flags & (~( 0x01 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x01 ));

	proto_tree_add_boolean(tree, hf_witness_witness_interfaceInfo_flags_IPv6_VALID, tvb, offset-4, 4, flags);
	if (flags&( 0x02 )){
		proto_item_append_text(item, "IPv6_VALID");
		if (flags & (~( 0x02 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x02 ));

	proto_tree_add_boolean(tree, hf_witness_witness_interfaceInfo_flags_WITNESS_IF, tvb, offset-4, 4, flags);
	if (flags&( 0x04 )){
		proto_item_append_text(item, "WITNESS_IF");
		if (flags & (~( 0x04 )))
			proto_item_append_text(item, ", ");
	}
	flags&=(~( 0x04 ));

	if (flags) {
		proto_item_append_text(item, "Unknown bitmap value 0x%x", flags);
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	[to_null(1)] [charset(UTF16)] uint16 group_name[260]; */
/* IDL: 	witness_version version; */
/* IDL: 	witness_interfaceInfo_state state; */
/* IDL: 	[flag(LIBNDR_FLAG_BIGENDIAN)] ipv4address ipv4; */
/* IDL: 	[flag(LIBNDR_FLAG_BIGENDIAN)] ipv6address ipv6; */
/* IDL: 	witness_interfaceInfo_flags flags; */
/* IDL: } */

static int
witness_dissect_element_interfaceInfo_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_enum_version(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceInfo_version, 0);

	return offset;
}

static int
witness_dissect_element_interfaceInfo_state(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_enum_interfaceInfo_state(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceInfo_state, 0);

	return offset;
}

static int
witness_dissect_element_interfaceInfo_ipv4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=PIDL_dissect_ipv4address(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceInfo_ipv4, PIDL_SET_COL_INFO);

	return offset;
}

static int
witness_dissect_element_interfaceInfo_ipv6(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset=PIDL_dissect_ipv6address(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceInfo_ipv6, PIDL_SET_COL_INFO);

	return offset;
}

static int
witness_dissect_element_interfaceInfo_flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_bitmap_interfaceInfo_flags(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceInfo_flags, 0);

	return offset;
}

int
witness_dissect_struct_interfaceInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	dcerpc_info *di = pinfo->private_data;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_witness_witness_interfaceInfo);
	}

	offset = witness_dissect_element_interfaceInfo_group_name(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceInfo_version(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceInfo_state(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceInfo_ipv4(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceInfo_ipv6(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceInfo_flags(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);


	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_4_BYTES;
	}

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 num_interfaces; */
/* IDL: 	[unique(1)] [size_is(num_interfaces)] witness_interfaceInfo *interfaces; */
/* IDL: } */

static int
witness_dissect_element_interfaceList_num_interfaces(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_witness_witness_interfaceList_num_interfaces, 0);

	return offset;
}

static int
witness_dissect_element_interfaceList_interfaces(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_interfaceList_interfaces_, NDR_POINTER_UNIQUE, "Pointer to Interfaces (witness_interfaceInfo)",hf_witness_witness_interfaceList_interfaces);

	return offset;
}

static int
witness_dissect_element_interfaceList_interfaces_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, witness_dissect_element_interfaceList_interfaces__);

	return offset;
}

static int
witness_dissect_element_interfaceList_interfaces__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_struct_interfaceInfo(tvb,offset,pinfo,tree,drep,hf_witness_witness_interfaceList_interfaces,0);

	return offset;
}

int
witness_dissect_struct_interfaceList(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	dcerpc_info *di = pinfo->private_data;
	int old_offset;

	ALIGN_TO_5_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_witness_witness_interfaceList);
	}

	offset = witness_dissect_element_interfaceList_num_interfaces(tvb, offset, pinfo, tree, drep);

	offset = witness_dissect_element_interfaceList_interfaces(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);


	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}


/* IDL: enum { */
/* IDL: 	RESOURCE_CHANGE=1, */
/* IDL: 	CLIENT_MOVE=2, */
/* IDL: 	SHARE_MOVE=3, */
/* IDL: 	IP_CHANGE=4, */
/* IDL: } */

int
witness_dissect_enum_notifyResponse_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_)
{
	guint1632 parameter=0;
	if(param){
		parameter=(guint1632)*param;
	}
	offset = dissect_ndr_uint1632(tvb, offset, pinfo, tree, drep, hf_index, &parameter);
	if(param){
		*param=(guint32)parameter;
	}
	return offset;
}


/* IDL: struct { */
/* IDL: 	witness_notifyResponse_type message_type; */
/* IDL: 	uint32 length; */
/* IDL: 	uint32 num_messages; */
/* IDL: 	[unique(1)] [size_is(length)] uint8 *message_buffer; */
/* IDL: } */

static int
witness_dissect_element_notifyResponse_message_type(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_enum_notifyResponse_type(tvb, offset, pinfo, tree, drep, hf_witness_witness_notifyResponse_message_type, 0);

	return offset;
}

static int
witness_dissect_element_notifyResponse_length(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_witness_witness_notifyResponse_length, 0);

	return offset;
}

static int
witness_dissect_element_notifyResponse_num_messages(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_witness_witness_notifyResponse_num_messages, 0);

	return offset;
}

static int
witness_dissect_element_notifyResponse_message_buffer(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_notifyResponse_message_buffer_, NDR_POINTER_UNIQUE, "Pointer to Message Buffer (uint8)",hf_witness_witness_notifyResponse_message_buffer);

	return offset;
}

static int
witness_dissect_element_notifyResponse_message_buffer__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_witness_witness_notifyResponse_message_buffer, 0);

	return offset;
}

static int
witness_dissect_element_GetInterfaceList_interface_list(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_GetInterfaceList_interface_list_, NDR_POINTER_REF, "Pointer to Interface List (witness_interfaceList)",hf_witness_witness_GetInterfaceList_interface_list);

	return offset;
}

static int
witness_dissect_element_GetInterfaceList_interface_list_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_GetInterfaceList_interface_list__, NDR_POINTER_UNIQUE, "Pointer to Interface List (witness_interfaceList)",hf_witness_witness_GetInterfaceList_interface_list);

	return offset;
}

static int
witness_dissect_element_GetInterfaceList_interface_list__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_struct_interfaceList(tvb,offset,pinfo,tree,drep,hf_witness_witness_GetInterfaceList_interface_list,0);

	return offset;
}

/* IDL: WERROR witness_GetInterfaceList( */
/* IDL: [out] [ref] witness_interfaceList **interface_list */
/* IDL: ); */

static int
witness_dissect_GetInterfaceList_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="GetInterfaceList";
	offset = witness_dissect_element_GetInterfaceList_interface_list(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_witness_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
witness_dissect_GetInterfaceList_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="GetInterfaceList";
	return offset;
}

static int
witness_dissect_element_Register_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_Register_context_handle_, NDR_POINTER_REF, "Pointer to Context Handle (policy_handle)",hf_witness_context_handle);

	return offset;
}

static int
witness_dissect_element_Register_context_handle_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_witness_context_handle, PIDL_POLHND_OPEN);

	return offset;
}

static int
witness_dissect_element_Register_version(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_enum_version(tvb, offset, pinfo, tree, drep, hf_witness_witness_Register_version, 0);

	return offset;
}

static int
witness_dissect_element_Register_net_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_Register_net_name_, NDR_POINTER_UNIQUE, "Pointer to Net Name (uint16)",hf_witness_witness_Register_net_name);

	return offset;
}

static int
witness_dissect_element_Register_net_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_witness_witness_Register_net_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
witness_dissect_element_Register_ip_address(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_Register_ip_address_, NDR_POINTER_UNIQUE, "Pointer to Ip Address (uint16)",hf_witness_witness_Register_ip_address);

	return offset;
}

static int
witness_dissect_element_Register_ip_address_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_witness_witness_Register_ip_address, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
witness_dissect_element_Register_client_computer_name(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_Register_client_computer_name_, NDR_POINTER_UNIQUE, "Pointer to Client Computer Name (uint16)",hf_witness_witness_Register_client_computer_name);

	return offset;
}

static int
witness_dissect_element_Register_client_computer_name_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_witness_witness_Register_client_computer_name, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR witness_Register( */
/* IDL: [out] [ref] policy_handle *context_handle, */
/* IDL: [in] witness_version version, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *net_name, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *ip_address, */
/* IDL: [unique(1)] [in] [charset(UTF16)] uint16 *client_computer_name */
/* IDL: ); */

static int
witness_dissect_Register_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="Register";
	offset = witness_dissect_element_Register_context_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_witness_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
witness_dissect_Register_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="Register";
	offset = witness_dissect_element_Register_version(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = witness_dissect_element_Register_net_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = witness_dissect_element_Register_ip_address(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = witness_dissect_element_Register_client_computer_name(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
witness_dissect_element_UnRegister_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_witness_context_handle, PIDL_POLHND_CLOSE);

	return offset;
}

/* IDL: WERROR witness_UnRegister( */
/* IDL: [in] policy_handle context_handle */
/* IDL: ); */

static int
witness_dissect_UnRegister_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="UnRegister";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_witness_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
witness_dissect_UnRegister_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="UnRegister";
	offset = witness_dissect_element_UnRegister_context_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
witness_dissect_element_AsyncNotify_context_handle(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_witness_context_handle, 0);

	return offset;
}

static int
witness_dissect_element_AsyncNotify_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_AsyncNotify_response_, NDR_POINTER_REF, "Pointer to Response (witness_notifyResponse)",hf_witness_witness_AsyncNotify_response);

	return offset;
}

static int
witness_dissect_element_AsyncNotify_response_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, witness_dissect_element_AsyncNotify_response__, NDR_POINTER_UNIQUE, "Pointer to Response (witness_notifyResponse)",hf_witness_witness_AsyncNotify_response);

	return offset;
}

static int
witness_dissect_element_AsyncNotify_response__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = witness_dissect_struct_notifyResponse(tvb,offset,pinfo,tree,drep,hf_witness_witness_AsyncNotify_response,0);

	return offset;
}

/* IDL: WERROR witness_AsyncNotify( */
/* IDL: [in] policy_handle context_handle, */
/* IDL: [out] [ref] witness_notifyResponse **response */
/* IDL: ); */

static int
witness_dissect_AsyncNotify_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="AsyncNotify";
	offset = witness_dissect_element_AsyncNotify_response(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_witness_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
witness_dissect_AsyncNotify_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="AsyncNotify";
	offset = witness_dissect_element_AsyncNotify_context_handle(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}


static dcerpc_sub_dissector witness_dissectors[] = {
	{ 0, "GetInterfaceList",
	   witness_dissect_GetInterfaceList_request, witness_dissect_GetInterfaceList_response},
	{ 1, "Register",
	   witness_dissect_Register_request, witness_dissect_Register_response},
	{ 2, "UnRegister",
	   witness_dissect_UnRegister_request, witness_dissect_UnRegister_response},
	{ 3, "AsyncNotify",
	   witness_dissect_AsyncNotify_request, witness_dissect_AsyncNotify_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_witness(void)
{
	static hf_register_info hf[] = {
	{ &hf_witness_move_ipaddr_list_flags,
	  { "Flags", "witness.move_ipaddr.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_notifyResponse_num_messages,
	  { "Num Messages", "witness.witness_notifyResponse.num_messages", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_notifyResponse_message_type,
	  { "Message Type", "witness.witness_notifyResponse.message_type", FT_UINT1632, BASE_DEC, VALS(witness_witness_notifyResponse_type_vals), 0, NULL, HFILL }},
	{ &hf_witness_werror,
	  { "Windows Error", "witness.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_witness_witness_Register_version,
	  { "Version", "witness.witness_Register.version", FT_UINT32, BASE_DEC, VALS(witness_witness_version_vals), 0, NULL, HFILL }},
	{ &hf_witness_witness_Register_client_computer_name,
	  { "Client Computer Name", "witness.witness_Register.client_computer_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceList_num_interfaces,
	  { "Num Interfaces", "witness.witness_interfaceList.num_interfaces", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_context_handle,
	  { "Handle", "witness.handle", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceList_interfaces,
	  { "Interfaces", "witness.witness_interfaceList.interfaces", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_move_ipaddr_list_ipv6,
	  { "IPv6", "witness.move_ipaddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_AsyncNotify_response,
	  { "Response", "witness.witness_AsyncNotify.response", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_opnum,
	  { "Operation", "witness.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_version,
	  { "Version", "witness.witness_interfaceInfo.version", FT_UINT32, BASE_DEC, VALS(witness_witness_version_vals), 0, NULL, HFILL }},
	{ &hf_witness_change_type,
	  { "Type", "witness.change.type", FT_UINT32, BASE_HEX, VALS(witness_change_type_vals), 0, NULL, HFILL }},
	{ &hf_witness_move_ipaddr_list_flags_ipv4,
	  { "IPv4", "witness.move_ipaddr.ipv4_valid", FT_BOOLEAN, 32, TFS(&valid_tfs), 0x01, NULL, HFILL }},
	{ &hf_dcerpc_array_max_count,
	  { "Max Count", "dcerpc.array.max_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_flags_WITNESS_IF,
	  { "Witness If", "witness.witness_interfaceInfo_flags.WITNESS_IF", FT_BOOLEAN, 32, TFS(&witness_interfaceInfo_flags_WITNESS_IF_tfs), ( 0x04 ), NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_group_name,
	  { "Group Name", "witness.witness_interfaceInfo.group_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_flags_IPv6_VALID,
	  { "Ipv6 Valid", "witness.witness_interfaceInfo_flags.IPv6_VALID", FT_BOOLEAN, 32, TFS(&witness_interfaceInfo_flags_IPv6_VALID_tfs), ( 0x02 ), NULL, HFILL }},
	{ &hf_witness_move_ipaddr_list_flags_ipv6,
	  { "IPv6", "witness.move_ipaddr.ipv6_valid", FT_BOOLEAN, 32, TFS(&valid_tfs), 0x02, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_flags_IPv4_VALID,
	  { "Ipv4 Valid", "witness.witness_interfaceInfo_flags.IPv4_VALID", FT_BOOLEAN, 32, TFS(&witness_interfaceInfo_flags_IPv4_VALID_tfs), ( 0x01 ), NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_flags,
	  { "Flags", "witness.witness_interfaceInfo.flags", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_ipv6,
	  { "Ipv6", "witness.witness_interfaceInfo.ipv6", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_ipv4,
	  { "Ipv4", "witness.witness_interfaceInfo.ipv4", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_change_name,
	  { "Name", "witness.change.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_interfaceInfo_state,
	  { "State", "witness.witness_interfaceInfo.state", FT_UINT16, BASE_DEC, VALS(witness_witness_interfaceInfo_state_vals), 0, NULL, HFILL }},
	{ &hf_witness_witness_notifyResponse_length,
	  { "Length", "witness.witness_notifyResponse.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_move_ipaddr_list_ipv4,
	  { "IPv4", "witness.move_ipaddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_notifyResponse_message_buffer,
	  { "Message Buffer", "witness.witness_notifyResponse.message_buffer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_GetInterfaceList_interface_list,
	  { "Interface List", "witness.witness_GetInterfaceList.interface_list", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_Register_net_name,
	  { "Net Name", "witness.witness_Register.net_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_witness_witness_Register_ip_address,
	  { "Ip Address", "witness.witness_Register.ip_address", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_witness_move_ipaddr_list_flags,
		&ett_witness_move_ipaddr,
		&ett_message_buffer,
		&ett_dcerpc_witness,
		&ett_witness_witness_interfaceInfo_flags,
		&ett_witness_witness_interfaceInfo,
		&ett_witness_witness_interfaceList,
		&ett_witness_witness_notifyResponse,
	};

	proto_dcerpc_witness = proto_register_protocol("SMB Witness Service", "WITNESS", "witness");
	proto_register_field_array(proto_dcerpc_witness, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_witness(void)
{
	dcerpc_init_uuid(proto_dcerpc_witness, ett_dcerpc_witness,
		&uuid_dcerpc_witness, ver_dcerpc_witness,
		witness_dissectors, hf_witness_opnum);
}
