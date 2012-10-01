
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
	guint8 *data;
	guint32 size;
};

struct data_str {
	char *str;
	guint32 len;
};

struct vt_decimal {
	guint32 hi, lo, mid;
};


struct vt_vector {
	guint32 len;
	union  {
		gint8 *vt_i1;
		guint8 *vt_ui1;
		gint16 *vt_i2;
		guint16 *vt_ui2, *vt_bool;
		gint32 *vt_i4;
		guint32 *vt_ui4, *vt_error;
		gint64 *vt_i8, *vt_cy, *vt_filetime;
		guint64 *vt_ui8;
		float *vt_r4;
		double *vt_r8, *vt_date;
		e_guid_t *vt_clsid;
		struct data_blob *vt_blob, *vt_blob_object;
		struct data_str *vt_lpstr, *vt_lpwstr, *vt_compressed_lpwstr, *vt_bstr;
	} u;
};

struct SAFEARRAYBOUNDS {
	guint32 cElements, lLbound;
};

struct vt_array {
	struct vt_vector vData;
	guint16 cDims, fFeature;
	guint32 cbElements;

	struct SAFEARRAYBOUNDS *Rgsabound;
};

union vValue {
	union {
		gint8 vt_i1;
		guint8 vt_ui1;
		gint16 vt_i2;
		guint16 vt_ui2, vt_bool;
		gint32 vt_i4, vt_int;
		guint32 vt_ui4, vt_uint, vt_error;
		gint64 vt_i8, vt_cy, vt_filetime;
		guint64 vt_ui8;
		double vt_r8, vt_date;
		e_guid_t vt_clsid;
		float vt_r4;
		struct vt_decimal vt_decimal;
		struct data_blob vt_blob, vt_blob_object;
		struct data_str vt_lpstr, vt_lpwstr, vt_compressed_lpwstr, vt_bstr;
	} vt_single;
	struct vt_vector vt_vector;
	struct vt_array vt_array;
};

struct vtype {
	enum vType tag; /* base type, hight bits cleared */
	const char *str;  /* string rep of base type */
	int size;        /* -1 for variable length */
	int (*tvb_get)(tvbuff_t*, int, void*);
	void (*strbuf_append)(emem_strbuf_t*, void*);
};

/* 2.2.1.1 */
struct CBaseStorageVariant {
	enum vType vType;
	guint16 vData1;
	guint16 vData2;
	union vValue vValue;

	struct vtype *type;
};

/*****************************************************/


enum rType {
	RTNone = 0,
	RTAnd,
	RTOr,
	RTNot,
	RTContent,
	RTProperty,
	RTProximity,
	RTVector,
	RTNatLanguage,
	RTScope,
	RTCoerce_Add,
	RTCoerce_Multiply,
	RTCoerce_Absolute,
	RTProb,
	RTFeedback,
	RTReldoc,
	RTReuseWhere = 0x11,
	RTInternalProp = 0x00fffffa,
	RTPhrase = 0x00fffffd,
};


struct CRestriction;

/* 2.2.1.6*/
struct CNodeRestriction {
	guint32 cNode;
	struct CRestriction *paNode;
};

/* 2.2.1.17 */
struct CRestriction {
	enum rType ulType;
	guint32 Weight;
	union {
		//	void RTNone;
		struct CNodeRestriction *RTAnd, *RTOr, *RTProximity, *RTPhrase;
		struct CRestriction *RTNot;
		struct CContentRestriction *RTContent;
		struct CPropertyRestriction *RTProperty;
		struct CVectorRestriction *RTVector;
		struct CNatLanguageRestriction *RTNatLanguage;
		struct CScopeRestriction *RTScope;
		struct CReuseWhere *RTReuseWhere;
		struct CInternalPropertyRestriction *RTInternalProp;
		struct CCoercionRestriction *RTCoerce_Add, *RTCoerce_Multiply, *RTCoerce_Absolute;
	} u;
};
