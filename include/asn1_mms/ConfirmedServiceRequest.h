/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "MMS"
 * 	found in "mms.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_ConfirmedServiceRequest_H_
#define	_ConfirmedServiceRequest_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GetNameListRequest.h"
#include "ReadRequest.h"
#include "WriteRequest.h"
#include "GetVariableAccessAttributesRequest.h"
#include "DefineNamedVariableListRequest.h"
#include "GetNamedVariableListAttributesRequest.h"
#include "DeleteNamedVariableListRequest.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ConfirmedServiceRequest_PR {
	ConfirmedServiceRequest_PR_NOTHING,	/* No components present */
	ConfirmedServiceRequest_PR_getNameList,
	ConfirmedServiceRequest_PR_read,
	ConfirmedServiceRequest_PR_write,
	ConfirmedServiceRequest_PR_getVariableAccessAttributes,
	ConfirmedServiceRequest_PR_defineNamedVariableList,
	ConfirmedServiceRequest_PR_getNamedVariableListAttributes,
	ConfirmedServiceRequest_PR_deleteNamedVariableList
} ConfirmedServiceRequest_PR;

/* ConfirmedServiceRequest */
typedef struct ConfirmedServiceRequest {
	ConfirmedServiceRequest_PR present;
	union ConfirmedServiceRequest_u {
		GetNameListRequest_t	 getNameList;
		ReadRequest_t	 read;
		WriteRequest_t	 write;
		GetVariableAccessAttributesRequest_t	 getVariableAccessAttributes;
		DefineNamedVariableListRequest_t	 defineNamedVariableList;
		GetNamedVariableListAttributesRequest_t	 getNamedVariableListAttributes;
		DeleteNamedVariableListRequest_t	 deleteNamedVariableList;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ConfirmedServiceRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ConfirmedServiceRequest;
extern asn_CHOICE_specifics_t asn_SPC_ConfirmedServiceRequest_specs_1;
extern asn_TYPE_member_t asn_MBR_ConfirmedServiceRequest_1[7];
extern asn_per_constraints_t asn_PER_type_ConfirmedServiceRequest_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ConfirmedServiceRequest_H_ */
#include "asn_internal.h"
