/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ISO8823-PRESENTATION"
 * 	found in "ISO8823_NEW.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Presentation_context_definition_list_H_
#define	_Presentation_context_definition_list_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Context-list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Presentation-context-definition-list */
typedef Context_list_t	 Presentation_context_definition_list_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Presentation_context_definition_list_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Presentation_context_definition_list;
asn_struct_free_f Presentation_context_definition_list_free;
asn_struct_print_f Presentation_context_definition_list_print;
asn_constr_check_f Presentation_context_definition_list_constraint;
ber_type_decoder_f Presentation_context_definition_list_decode_ber;
der_type_encoder_f Presentation_context_definition_list_encode_der;
xer_type_decoder_f Presentation_context_definition_list_decode_xer;
xer_type_encoder_f Presentation_context_definition_list_encode_xer;
oer_type_decoder_f Presentation_context_definition_list_decode_oer;
oer_type_encoder_f Presentation_context_definition_list_encode_oer;
per_type_decoder_f Presentation_context_definition_list_decode_uper;
per_type_encoder_f Presentation_context_definition_list_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Presentation_context_definition_list_H_ */
#include <asn_internal.h>
