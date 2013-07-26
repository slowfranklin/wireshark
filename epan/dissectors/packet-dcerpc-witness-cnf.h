struct notify_response {
	guint32 length;
	guint32 num;
	guint32 type;
};

int
dissect_message_buffer(tvbuff_t *tvb, gint offset, packet_info *pinfo,
		       proto_tree *tree, guint8 *drep, struct notify_response *resp);
