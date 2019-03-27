/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ISO8823-PRESENTATION"
 * 	found in "ISO8823_NEW.asn1"
 * 	`asn1c -fcompound-names`
 */

#include "CP-type.h"

static const ber_tlv_tag_t asn_DEF_extensions_tags_13[] = {
	(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SEQUENCE_specifics_t asn_SPC_extensions_specs_13 = {
	sizeof(struct CP_type__normal_mode_parameters__extensions),
	offsetof(struct CP_type__normal_mode_parameters__extensions, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_extensions_13 = {
	"extensions",
	"extensions",
	&asn_OP_SEQUENCE,
	asn_DEF_extensions_tags_13,
	sizeof(asn_DEF_extensions_tags_13)
		/sizeof(asn_DEF_extensions_tags_13[0]), /* 2 */
	asn_DEF_extensions_tags_13,	/* Same as above */
	sizeof(asn_DEF_extensions_tags_13)
		/sizeof(asn_DEF_extensions_tags_13[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	0, 0,	/* No members */
	&asn_SPC_extensions_specs_13	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_normal_mode_parameters_3[] = {
	{ ATF_POINTER, 11, offsetof(struct CP_type__normal_mode_parameters, protocol_version),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Protocol_version,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"protocol-version"
		},
	{ ATF_POINTER, 10, offsetof(struct CP_type__normal_mode_parameters, calling_presentation_selector),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Calling_presentation_selector,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"calling-presentation-selector"
		},
	{ ATF_POINTER, 9, offsetof(struct CP_type__normal_mode_parameters, called_presentation_selector),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Called_presentation_selector,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"called-presentation-selector"
		},
	{ ATF_POINTER, 8, offsetof(struct CP_type__normal_mode_parameters, presentation_context_definition_list),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Presentation_context_definition_list,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"presentation-context-definition-list"
		},
	{ ATF_POINTER, 7, offsetof(struct CP_type__normal_mode_parameters, default_context_name),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Default_context_name,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"default-context-name"
		},
	{ ATF_POINTER, 6, offsetof(struct CP_type__normal_mode_parameters, presentation_requirements),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Presentation_requirements,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"presentation-requirements"
		},
	{ ATF_POINTER, 5, offsetof(struct CP_type__normal_mode_parameters, user_session_requirements),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_User_session_requirements,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"user-session-requirements"
		},
	{ ATF_POINTER, 4, offsetof(struct CP_type__normal_mode_parameters, protocol_options),
		(ASN_TAG_CLASS_CONTEXT | (11 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Protocol_options,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"protocol-options"
		},
	{ ATF_POINTER, 3, offsetof(struct CP_type__normal_mode_parameters, initiators_nominated_context),
		(ASN_TAG_CLASS_CONTEXT | (12 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Presentation_context_identifier,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"initiators-nominated-context"
		},
	{ ATF_POINTER, 2, offsetof(struct CP_type__normal_mode_parameters, extensions),
		(ASN_TAG_CLASS_CONTEXT | (14 << 2)),
		0,
		&asn_DEF_extensions_13,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"extensions"
		},
	{ ATF_POINTER, 1, offsetof(struct CP_type__normal_mode_parameters, user_data),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_User_data,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"user-data"
		},
};
static const int asn_MAP_normal_mode_parameters_oms_3[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
static const ber_tlv_tag_t asn_DEF_normal_mode_parameters_tags_3[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_normal_mode_parameters_tag2el_3[] = {
    { (ASN_TAG_CLASS_APPLICATION | (0 << 2)), 10, 0, 0 }, /* simply-encoded-data */
    { (ASN_TAG_CLASS_APPLICATION | (1 << 2)), 10, 0, 0 }, /* fully-encoded-data */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* protocol-version */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* calling-presentation-selector */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* called-presentation-selector */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 3, 0, 0 }, /* presentation-context-definition-list */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 4, 0, 0 }, /* default-context-name */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 5, 0, 0 }, /* presentation-requirements */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 6, 0, 0 }, /* user-session-requirements */
    { (ASN_TAG_CLASS_CONTEXT | (11 << 2)), 7, 0, 0 }, /* protocol-options */
    { (ASN_TAG_CLASS_CONTEXT | (12 << 2)), 8, 0, 0 }, /* initiators-nominated-context */
    { (ASN_TAG_CLASS_CONTEXT | (14 << 2)), 9, 0, 0 } /* extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_normal_mode_parameters_specs_3 = {
	sizeof(struct CP_type__normal_mode_parameters),
	offsetof(struct CP_type__normal_mode_parameters, _asn_ctx),
	asn_MAP_normal_mode_parameters_tag2el_3,
	12,	/* Count of tags in the map */
	asn_MAP_normal_mode_parameters_oms_3,	/* Optional members */
	11, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_normal_mode_parameters_3 = {
	"normal-mode-parameters",
	"normal-mode-parameters",
	&asn_OP_SEQUENCE,
	asn_DEF_normal_mode_parameters_tags_3,
	sizeof(asn_DEF_normal_mode_parameters_tags_3)
		/sizeof(asn_DEF_normal_mode_parameters_tags_3[0]) - 1, /* 1 */
	asn_DEF_normal_mode_parameters_tags_3,	/* Same as above */
	sizeof(asn_DEF_normal_mode_parameters_tags_3)
		/sizeof(asn_DEF_normal_mode_parameters_tags_3[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_normal_mode_parameters_3,
	11,	/* Elements count */
	&asn_SPC_normal_mode_parameters_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_CP_type_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CP_type, mode_selector),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Mode_selector,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"mode-selector"
		},
	{ ATF_POINTER, 1, offsetof(struct CP_type, normal_mode_parameters),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_normal_mode_parameters_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"normal-mode-parameters"
		},
};
static const ber_tlv_tag_t asn_DEF_CP_type_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CP_type_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* mode-selector */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 } /* normal-mode-parameters */
};
static const uint8_t asn_MAP_CP_type_mmap_1[(2 + (8 * sizeof(unsigned int)) - 1) / 8] = {
	(1 << 7) | (0 << 6)
};
static 
asn_SET_specifics_t asn_SPC_CP_type_specs_1 = {
	sizeof(struct CP_type),
	offsetof(struct CP_type, _asn_ctx),
	offsetof(struct CP_type, _presence_map),
	asn_MAP_CP_type_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_CP_type_tag2el_1,	/* Same as above */
	2,	/* Count of tags in the CXER map */
	0,	/* Whether extensible */
	(const unsigned int *)asn_MAP_CP_type_mmap_1	/* Mandatory elements map */
};
asn_TYPE_descriptor_t asn_DEF_CP_type = {
	"CP-type",
	"CP-type",
	&asn_OP_SET,
	asn_DEF_CP_type_tags_1,
	sizeof(asn_DEF_CP_type_tags_1)
		/sizeof(asn_DEF_CP_type_tags_1[0]), /* 1 */
	asn_DEF_CP_type_tags_1,	/* Same as above */
	sizeof(asn_DEF_CP_type_tags_1)
		/sizeof(asn_DEF_CP_type_tags_1[0]), /* 1 */
	{ 0, 0, SET_constraint },
	asn_MBR_CP_type_1,
	2,	/* Elements count */
	&asn_SPC_CP_type_specs_1	/* Additional specs */
};

