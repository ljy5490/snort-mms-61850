/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#include "InitiateResponsePdu.h"

asn_TYPE_member_t asn_MBR_InitiateResponsePdu_1[] = {
	{ ATF_POINTER, 1, offsetof(struct InitiateResponsePdu, localDetailCalled),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Integer32,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"localDetailCalled"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InitiateResponsePdu, negotiatedMaxServOutstandingCalling),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Integer16,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"negotiatedMaxServOutstandingCalling"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InitiateResponsePdu, negotiatedMaxServOutstandingCalled),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Integer16,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"negotiatedMaxServOutstandingCalled"
		},
	{ ATF_POINTER, 1, offsetof(struct InitiateResponsePdu, negotiatedDataStructureNestingLevel),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Integer8,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"negotiatedDataStructureNestingLevel"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InitiateResponsePdu, mmsInitResponseDetail),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InitResponseDetail,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mmsInitResponseDetail"
		},
};
static const int asn_MAP_InitiateResponsePdu_oms_1[] = { 0, 3 };
static const ber_tlv_tag_t asn_DEF_InitiateResponsePdu_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InitiateResponsePdu_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* localDetailCalled */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* negotiatedMaxServOutstandingCalling */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* negotiatedMaxServOutstandingCalled */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* negotiatedDataStructureNestingLevel */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* mmsInitResponseDetail */
};
asn_SEQUENCE_specifics_t asn_SPC_InitiateResponsePdu_specs_1 = {
	sizeof(struct InitiateResponsePdu),
	offsetof(struct InitiateResponsePdu, _asn_ctx),
	asn_MAP_InitiateResponsePdu_tag2el_1,
	5,	/* Count of tags in the map */
	asn_MAP_InitiateResponsePdu_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InitiateResponsePdu = {
	"InitiateResponsePdu",
	"InitiateResponsePdu",
	&asn_OP_SEQUENCE,
	asn_DEF_InitiateResponsePdu_tags_1,
	sizeof(asn_DEF_InitiateResponsePdu_tags_1)
		/sizeof(asn_DEF_InitiateResponsePdu_tags_1[0]), /* 1 */
	asn_DEF_InitiateResponsePdu_tags_1,	/* Same as above */
	sizeof(asn_DEF_InitiateResponsePdu_tags_1)
		/sizeof(asn_DEF_InitiateResponsePdu_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_InitiateResponsePdu_1,
	5,	/* Elements count */
	&asn_SPC_InitiateResponsePdu_specs_1	/* Additional specs */
};

