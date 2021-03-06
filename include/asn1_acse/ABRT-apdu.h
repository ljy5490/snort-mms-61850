/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ACSE-1"
 * 	found in "ACSE.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_ABRT_apdu_H_
#define	_ABRT_apdu_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ABRT-source.h"
#include "ABRT-diagnostic.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Association_information;

/* ABRT-apdu */
typedef struct ABRT_apdu {
	ABRT_source_t	 abort_source;
	ABRT_diagnostic_t	*abort_diagnostic;	/* OPTIONAL */
	struct Association_information	*user_information;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ABRT_apdu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ABRT_apdu;
extern asn_SEQUENCE_specifics_t asn_SPC_ABRT_apdu_specs_1;
extern asn_TYPE_member_t asn_MBR_ABRT_apdu_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Association-information.h"

#endif	/* _ABRT_apdu_H_ */
#include <asn_internal.h>
