
enum vType {
    VT_EMPTY       = 0x00,
    VT_NULL        = 0x01,
    VT_I2          = 0x02,
    VT_I4          = 0x03,
    VT_R4          = 0x04,
    VT_R8          = 0x05,
    VT_CY          = 0x06,
    VT_DATE        = 0x07,
    VT_BSTR        = 0x08,
    VT_ERROR       = 0x0a,
    VT_BOOL        = 0x0b,
    VT_VARIANT     = 0x0c,
    VT_DECIMAL     = 0x0e,
    VT_I1          = 0x10,
    VT_UI1         = 0x11,
    VT_UI2         = 0x12,
    VT_UI4         = 0x13,
    VT_I8          = 0x14,
    VT_UI8         = 0x15,
    VT_INT         = 0x16,
    VT_UINT        = 0x17,
    VT_LPSTR       = 0x1e,
    VT_LPWSTR      = 0x1f,
    VT_COMPRESSED_LPWSTR = 0x23,
    VT_FILETIME    = 0x40,
    VT_BLOB        = 0x41,
    VT_BLOB_OBJECT = 0x46,
    VT_CLSID       = 0x48,
    VT_VECTOR      = 0x1000,
    VT_ARRAY       = 0x2000,
};

struct data_blob {
	void *data;
	guint32 size;
};

struct data_str {
	char *str;
	guint32 len;
};

union vValue {
	gint8 vt_i1;
	guint8 vt_ui1;
	gint16 vt_i2;
	guint16 vt_ui2, vt_bool;
	gint32 vt_i4, vt_int;
	guint32 vt_ui4, vt_uint, vt_error;
	float vt_r4;
	gint64 vt_i8, vt_cy, vt_filetime;
	guint64 vt_ui8;
	double vt_r8, vt_date;
	e_guid_t vt_clsid;
	struct {
		guint32 hi, lo, mid;
	} vt_decimal;
	struct data_blob vt_blob, vt_blob_object;
	struct data_str vt_lpstr, vt_lpwstr, vt_compressed_lpwstr, vt_bstr;
	struct {
		guint32 len;
		union {
			gint8 *vt_i1;
			guint8 *vt_ui1;
			gint16 *vt_i2;
			guint16 *vt_ui2, *vt_bool;
			gint32 *vt_i4;
			guint32 *vt_ui4, *vt_error;
			float *vt_r4;
			gint64 *vt_i8, *vt_cy, *vt_filetime;
			guint64 *vt_ui8;
			double *vt_r8, *vt_date;
			e_guid_t *vt_clsid;
			struct data_blob *vt_blob, *vt_blob_object;
			struct data_str *vt_lpstr, *vt_lpwstr, *vt_compressed_lpwstr, *vt_bstr;
		};
	} vt_vector;
};

/* 2.2.1.1 */
struct CBaseStorageVariant {
	enum vType vType;
	enum vType vType_high;
	guint16 vData1;
	guint16 vData2;
	union vValue vValue;
};
