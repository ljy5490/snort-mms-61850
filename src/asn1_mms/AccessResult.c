/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#include "AccessResult.h"

static asn_oer_constraints_t asn_OER_type_AccessResult_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_AccessResult_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_AccessResult_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AccessResult, choice.failure),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DataAccessError,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"failure"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AccessResult, choice.success),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_Data,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"success"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_AccessResult_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* failure */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* array */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 }, /* structure */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 1, 0, 0 }, /* boolean-new */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 1, 0, 0 }, /* bit-string */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 1, 0, 0 }, /* integer */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 1, 0, 0 }, /* unsigned */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 1, 0, 0 }, /* floating-point */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 1, 0, 0 }, /* octet-string */
    { (ASN_TAG_CLASS_CONTEXT | (10 << 2)), 1, 0, 0 }, /* visible-string */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 1, 0, 0 }, /* binary-time */
    { (ASN_TAG_CLASS_CONTEXT | (16 << 2)), 1, 0, 0 }, /* mms-string */
    { (ASN_TAG_CLASS_CONTEXT | (17 << 2)), 1, 0, 0 } /* utc-time */
};
asn_CHOICE_specifics_t asn_SPC_AccessResult_specs_1 = {
	sizeof(struct AccessResult),
	offsetof(struct AccessResult, _asn_ctx),
	offsetof(struct AccessResult, present),
	sizeof(((struct AccessResult *)0)->present),
	asn_MAP_AccessResult_tag2el_1,
	13,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_AccessResult = {
	"AccessResult",
	"AccessResult",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_AccessResult_constr_1, &asn_PER_type_AccessResult_constr_1, CHOICE_constraint },
	asn_MBR_AccessResult_1,
	2,	/* Elements count */
	&asn_SPC_AccessResult_specs_1	/* Additional specs */
};
