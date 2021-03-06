/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ISO8823-PRESENTATION"
 * 	found in "ISO8823_NEW.asn1"
 * 	`asn1c -fcompound-names`
 */

#include "Presentation-context-deletion-result-list.h"

static asn_oer_constraints_t asn_OER_type_Presentation_context_deletion_result_list_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(0..7)) */};
static asn_per_constraints_t asn_PER_type_Presentation_context_deletion_result_list_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (SIZE(0..7)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_Presentation_context_deletion_result_list_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_Presentation_context_deletion_result_list_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_Presentation_context_deletion_result_list_specs_1 = {
	sizeof(struct Presentation_context_deletion_result_list),
	offsetof(struct Presentation_context_deletion_result_list, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_Presentation_context_deletion_result_list = {
	"Presentation-context-deletion-result-list",
	"Presentation-context-deletion-result-list",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_Presentation_context_deletion_result_list_tags_1,
	sizeof(asn_DEF_Presentation_context_deletion_result_list_tags_1)
		/sizeof(asn_DEF_Presentation_context_deletion_result_list_tags_1[0]), /* 1 */
	asn_DEF_Presentation_context_deletion_result_list_tags_1,	/* Same as above */
	sizeof(asn_DEF_Presentation_context_deletion_result_list_tags_1)
		/sizeof(asn_DEF_Presentation_context_deletion_result_list_tags_1[0]), /* 1 */
	{ &asn_OER_type_Presentation_context_deletion_result_list_constr_1, &asn_PER_type_Presentation_context_deletion_result_list_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_Presentation_context_deletion_result_list_1,
	1,	/* Single element */
	&asn_SPC_Presentation_context_deletion_result_list_specs_1	/* Additional specs */
};

