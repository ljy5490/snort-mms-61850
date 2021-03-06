/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_GetVariableAccessAttributesResponse_H_
#define	_GetVariableAccessAttributesResponse_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BOOLEAN.h"
#include "TypeSpecification.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GetVariableAccessAttributesResponse */
typedef struct GetVariableAccessAttributesResponse {
	BOOLEAN_t	 mmsDeletable;
	TypeSpecification_t	 typeSpecification;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} GetVariableAccessAttributesResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_GetVariableAccessAttributesResponse;
extern asn_SEQUENCE_specifics_t asn_SPC_GetVariableAccessAttributesResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_GetVariableAccessAttributesResponse_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _GetVariableAccessAttributesResponse_H_ */
#include "asn_internal.h"
