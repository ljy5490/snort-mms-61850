/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#include "DataAccessError.h"

/*
 * This type is implemented using NativeInteger,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_DataAccessError_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_DataAccessError = {
	"DataAccessError",
	"DataAccessError",
	&asn_OP_NativeInteger,
	asn_DEF_DataAccessError_tags_1,
	sizeof(asn_DEF_DataAccessError_tags_1)
		/sizeof(asn_DEF_DataAccessError_tags_1[0]), /* 1 */
	asn_DEF_DataAccessError_tags_1,	/* Same as above */
	sizeof(asn_DEF_DataAccessError_tags_1)
		/sizeof(asn_DEF_DataAccessError_tags_1[0]), /* 1 */
	{ 0, 0, NativeInteger_constraint },
	0, 0,	/* Defined elsewhere */
	0	/* No specifics */
};

