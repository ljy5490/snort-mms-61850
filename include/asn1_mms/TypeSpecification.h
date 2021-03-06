/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_TypeSpecification_H_
#define	_TypeSpecification_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NULL.h"
#include "Integer32.h"
#include "Unsigned8.h"
#include "BOOLEAN.h"
#include "Unsigned32.h"
#include "constr_SEQUENCE.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TypeSpecification_PR {
	TypeSpecification_PR_NOTHING,	/* No components present */
	TypeSpecification_PR_array,
	TypeSpecification_PR_structure,
	TypeSpecification_PR_boolean_new,
	TypeSpecification_PR_bit_string,
	TypeSpecification_PR_integer,
	TypeSpecification_PR_unsigned,
	TypeSpecification_PR_floating_point,
	TypeSpecification_PR_octet_string,
	TypeSpecification_PR_visible_string,
	TypeSpecification_PR_binary_time,
	TypeSpecification_PR_mms_string,
	TypeSpecification_PR_utc_time
} TypeSpecification_PR;

/* Forward declarations */
struct TypeSpecification;
struct StructComponent;

/* TypeSpecification */
typedef struct TypeSpecification {
	TypeSpecification_PR present;
	union TypeSpecification_u {
		struct TypeSpecification__array {
			BOOLEAN_t	 packed	/* DEFAULT FALSE */;
			Unsigned32_t	 numberOfElements;
			struct TypeSpecification	*elementType;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} array;
		struct TypeSpecification__structure {
			BOOLEAN_t	 packed	/* DEFAULT FALSE */;
			struct TypeSpecification__structure__components {
				A_SEQUENCE_OF(struct StructComponent) list;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} components;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} structure;
		NULL_t	 boolean_new;
		Integer32_t	 bit_string;
		Unsigned8_t	 integer;
		Unsigned8_t	 Unsigned;
		struct TypeSpecification__floating_point {
			Unsigned8_t	 format_width;
			Unsigned8_t	 exponent_width;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} floating_point;
		Integer32_t	 octet_string;
		Integer32_t	 visible_string;
		BOOLEAN_t	 binary_time;
		Integer32_t	 mms_string;
		NULL_t	 utc_time;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TypeSpecification_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TypeSpecification;
extern asn_CHOICE_specifics_t asn_SPC_TypeSpecification_specs_1;
extern asn_TYPE_member_t asn_MBR_TypeSpecification_1[12];
extern asn_per_constraints_t asn_PER_type_TypeSpecification_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TypeSpecification.h"
#include "StructComponent.h"

#endif	/* _TypeSpecification_H_ */
#include "asn_internal.h"
