#include "packet-smb-common.h"
#include "to_str.h"

struct notify_response {
	guint32 length;
	guint32 num;
	guint32 type;
};

static const int* witness_move_ipaddr_list_flags_fields[] = {
	&hf_witness_move_ipaddr_list_flags_ipv4,
	&hf_witness_move_ipaddr_list_flags_ipv6,
};

static const true_false_string valid_tfs = {
	"Valid", "Not valid"
};

static const value_string witness_change_type_vals[] = {
	{0x00, "Unknown"},
	{0x01, "Available"},
	{0xFF, "Unavailable"},
	{0, NULL}
};

static int witness_dissect_move_ipaddr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *ti = proto_tree_add_text(tree, tvb, offset, -1, "IP");
	proto_tree *tr = proto_item_add_subtree(ti, ett_witness_move_ipaddr);

	guint32 flags = tvb_get_letohl(tvb, offset);
	proto_tree_add_bitmask(tr, tvb, offset,
			       hf_witness_move_ipaddr_list_flags,
			       ett_witness_move_ipaddr_list_flags,
			       witness_move_ipaddr_list_flags_fields,
			       ENC_LITTLE_ENDIAN);
	offset  += 4;

	proto_tree_add_item(tr, hf_witness_move_ipaddr_list_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
	//proto_tree_add_ipv4
	if (flags & 1) {
		const char *ip = tvb_ip_to_str(tvb, offset);
		proto_item_append_text(tr, " %s", ip);
		proto_item_append_text(tree, " %s", ip);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", ip);
	}
	offset  += 4;

	proto_tree_add_item(tr, hf_witness_move_ipaddr_list_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
	//proto_tree_add_ipv6
	if (flags & 2) {
		const char *ip = tvb_ip6_to_str(tvb, offset);
		proto_item_append_text(tr, " %s", ip);
		proto_item_append_text(tree, " %s", ip);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", ip);
	}
	offset  += 16;

	proto_item_set_end(ti, tvb, offset);
	return offset;
}

static int witness_dissect_move_request(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 length, num, n;

	proto_item *ti = proto_tree_add_text(tree, tvb, offset, -1, "Move");
	proto_tree *tr = proto_item_add_subtree(ti, ett_message_buffer);

	length = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tr, tvb, offset, 4, "Length: %u", length);
	offset += 4;

	proto_tree_add_text(tr, tvb, offset, 4, "Reserved");
	offset += 4;

	num = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tr, tvb, offset, 4, "Num: %u", num);
	offset += 4;

	for (n=0; n<num; n++) {
		offset = witness_dissect_move_ipaddr(tvb, offset, pinfo, tr);
	}

	proto_item_set_end(ti, tvb, offset);
	return offset;
}



static int witness_dissect_resource_change(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint32 length, type;
	char *name;
	const int old_offset = offset;

	proto_item *ti = proto_tree_add_text(tree, tvb, offset, -1, "Change");
	proto_tree *tr = proto_item_add_subtree(ti, ett_message_buffer);

	length = tvb_get_letohl(tvb, offset);
	proto_tree_add_text(tr, tvb, offset, 4, "Length: %u", length);
	offset += 4;

	type = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tr, hf_witness_change_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	name = tvb_get_unicode_string(wmem_packet_scope(), tvb, offset, length-8, ENC_LITTLE_ENDIAN);
	proto_tree_add_string(tr, hf_witness_change_name, tvb, offset, length-8, name);

	proto_item_append_text(ti, ": %s -> %s", name,
			       val_to_str(type, witness_change_type_vals,
					  "Invalid (0x04%x)"));

	proto_item_set_len(ti, length);

	return old_offset + length;
}

static int
witness_dissect_notifyResponse_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
				       void * notify_response)
{
	const int old_offset = offset;
	int (*dissect)(tvbuff_t *, int, packet_info*, proto_tree *);
	const char *msg;
	unsigned n;

//	struct notify_response *resp = pinfo->private_data;
	struct notify_response *resp = notify_response;

	switch (resp->type) {
	case CLIENT_MOVE:
		msg = "Client Move";
		dissect = &witness_dissect_move_request;
		break;
	case RESOURCE_CHANGE:
		msg = "Resource Change";
		dissect = &witness_dissect_resource_change;
		break;
	case SHARE_MOVE:
		msg = "Share Move";
		dissect = &witness_dissect_move_request;
		break;
	case IP_CHANGE:
		msg = "IP Change";
		dissect = &witness_dissect_move_request;
		break;
	default:
		DISSECTOR_ASSERT(FALSE);
	}


	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", msg);

	for (n=0; n < resp->num; n++) {
		offset = dissect(tvb, offset, pinfo, tree);
	}

	DISSECTOR_ASSERT((unsigned)offset == (unsigned)old_offset + resp->length);
	return offset;
}

static int
dissect_ndr_ucbuffer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		     proto_tree *tree, dcerpc_info *di, guint8 *drep,
		     int (*dissect)(tvbuff_t *, int, packet_info*, proto_tree*, void*),
		     void *private_data)
{
	const int old_offset = offset;
	int conformance_size = di->call_data->flags & DCERPC_IS_NDR64 ? 8 : 4;

	if (di->conformant_run) {
		guint64 val;

		/* conformant run, just dissect the max_count header */
		di->conformant_run = 0;
		offset = dissect_ndr_uint3264(tvb, offset, pinfo, tree, di, drep,
					      hf_dcerpc_array_max_count, &val);
		di->array_max_count = (gint32)val;
		di->array_max_count_offset = offset-conformance_size;
		di->conformant_run = 1;
		di->conformant_eaten = offset-old_offset;
	} else {
		tvbuff_t *subtvb;

		/* we don't remember where in the bytestream this field was */
		proto_tree_add_uint(tree, hf_dcerpc_array_max_count, tvb,
				    di->array_max_count_offset, conformance_size,
				    di->array_max_count);

		/* real run, dissect the elements */
		tvb_ensure_bytes_exist(tvb, offset, di->array_max_count);
		subtvb = tvb_new_subset(tvb, offset, di->array_max_count, di->array_max_count);

//		pinfo->private_data = private_data;
		offset += dissect(subtvb, 0, pinfo, tree, private_data);
//		pinfo->private_data = di;

		DISSECTOR_ASSERT((unsigned)offset == (unsigned)old_offset + di->array_max_count);
    }

    return offset;
}

static int
witness_dissect_element_notifyResponse_message_buffer_(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info* di, guint8 *drep)
{
	offset = dissect_ndr_ucbuffer(tvb, offset, pinfo, tree, di, drep, witness_dissect_notifyResponse_message, di->private_data);

	return offset;
}

int
witness_dissect_struct_notifyResponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dcerpc_info* di, guint8 *drep, int hf_index, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	const int old_offset = offset;

	struct notify_response response;

	ALIGN_TO_5_BYTES;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_witness_witness_notifyResponse);
	}

	offset = witness_dissect_enum_notifyResponse_type(tvb, offset, pinfo, tree, di, drep,
							  hf_witness_witness_notifyResponse_message_type, &response.type);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_witness_witness_notifyResponse_length, &response.length);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep, hf_witness_witness_notifyResponse_num_messages, &response.num);

	if (!di->conformant_run) {
		if (di->private_data) {
			DISSECTOR_ASSERT(memcmp(di->private_data, &response, sizeof(response)) == 0);
		} else {
			di->private_data = ep_memdup(&response, sizeof(response));
		}
	}

	offset = witness_dissect_element_notifyResponse_message_buffer(tvb, offset, pinfo, tree, di, drep);

	proto_item_set_len(item, offset-old_offset);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

static int
witness_dissect_element_interfaceInfo_group_name(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *parent_tree, dcerpc_info *di _U_, guint8 *drep _U_)
{
	const gchar *str;
	int len = 260;
	guint16 bc = tvb_length_remaining(tvb, offset);

	str = get_unicode_or_ascii_string(tvb, &offset, TRUE, &len, TRUE, TRUE, &bc);

	if (str) {
		proto_item *pi;
		pi = proto_tree_add_string(parent_tree, hf_witness_witness_interfaceInfo_group_name, tvb, offset, 2*260, str);
		proto_item_append_text(pi, " [%d]", len);
		proto_item_append_text(parent_tree, ": %s", str);

	} else {
		//proto_tree_add_bytes
	}

	return offset + 2*260;
}

static int
PIDL_dissect_ipv4address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep _U_, int hfindex, guint32 param)
{
//	guint32 ip = tvb_get_ipv4(tvb,offset); //tvb_get_ntohl(tvb, offset);
	if (di->conformant_run) {
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}


	if (!di->no_align && (offset % 4)) {
		offset += 4 - (offset % 4);
	}

	proto_tree_add_item(tree, hfindex, tvb, offset, 4, ENC_BIG_ENDIAN);


	if (param & PIDL_SET_COL_INFO) {
		const char *ip = tvb_ip_to_str(tvb, offset);
		header_field_info *hf_info = proto_registrar_get_nth(hfindex);

		proto_item_append_text(proto_tree_get_parent(tree), " %s:%s", hf_info->name, ip);

		col_append_fstr(pinfo->cinfo, COL_INFO," %s:%s", hf_info->name, ip);
	}
	return offset + 4;
}

static int
PIDL_dissect_ipv6address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep _U_, int hfindex, guint32 param)
{
//	tvb_get_ipv6(tvb, offset, &addr);
	if (di->conformant_run) {
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}


	if (!di->no_align && (offset % 2)) {
		offset += 2 - (offset % 2);
	}

	proto_tree_add_item(tree, hfindex, tvb, offset, 16, ENC_BIG_ENDIAN);

	if (param & PIDL_SET_COL_INFO) {
		const char *ip = tvb_ip6_to_str(tvb, offset);
		header_field_info *hf_info = proto_registrar_get_nth(hfindex);

		proto_item_append_text(proto_tree_get_parent(tree), " %s:%s", hf_info->name, ip);

		col_append_fstr(pinfo->cinfo, COL_INFO," %s:%s", hf_info->name, ip);
	}

	return offset + 16;
}


int
witness_dissect_enum_interfaceInfo_state(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, dcerpc_info *di, guint8 *drep, int hf_index, guint32* param _U_)
{
	return PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_index, PIDL_SET_COL_INFO);
}
