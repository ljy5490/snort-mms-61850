/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#include "VariableSpecification.h"

static asn_oer_constraints_t asn_OER_type_VariableSpecification_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_VariableSpecification_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 0,  0,  0,  0 }	/* (0..0) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_VariableSpecification_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct VariableSpecification, choice.name),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ObjectName,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"name"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_VariableSpecification_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* name */
};
asn_CHOICE_specifics_t asn_SPC_VariableSpecification_specs_1 = {
	sizeof(struct VariableSpecification),
	offsetof(struct VariableSpecification, _asn_ctx),
	offsetof(struct VariableSpecification, present),
	sizeof(((struct VariableSpecification *)0)->present),
	asn_MAP_VariableSpecification_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_VariableSpecification = {
	"VariableSpecification",
	"VariableSpecification",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_VariableSpecification_constr_1, &asn_PER_type_VariableSpecification_constr_1, CHOICE_constraint },
	asn_MBR_VariableSpecification_1,
	1,	/* Elements count */
	&asn_SPC_VariableSpecification_specs_1	/* Additional specs */
};
