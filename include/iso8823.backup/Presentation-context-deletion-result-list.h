/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ISO8823-PRESENTATION"
 * 	found in "ISO8823_NEW.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Presentation_context_deletion_result_list_H_
#define	_Presentation_context_deletion_result_list_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Presentation-context-deletion-result-list */
typedef struct Presentation_context_deletion_result_list {
	A_SEQUENCE_OF(long) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Presentation_context_deletion_result_list_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Presentation_context_deletion_result_list;

#ifdef __cplusplus
}
#endif

#endif	/* _Presentation_context_deletion_result_list_H_ */
#include <asn_internal.h>
