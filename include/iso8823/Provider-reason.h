/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ISO8823-PRESENTATION"
 * 	found in "ISO8823_NEW.asn1"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Provider_reason_H_
#define	_Provider_reason_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Provider_reason {
	Provider_reason_reason_not_specified	= 0,
	Provider_reason_temporary_congestion	= 1,
	Provider_reason_local_limit_exceeded	= 2,
	Provider_reason_called_presentation_address_unknown	= 3,
	Provider_reason_protocol_version_not_supported	= 4,
	Provider_reason_default_context_not_supported	= 5,
	Provider_reason_user_data_not_readable	= 6,
	Provider_reason_no_PSAP_available	= 7
} e_Provider_reason;

/* Provider-reason */
typedef long	 Provider_reason_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Provider_reason;
asn_struct_free_f Provider_reason_free;
asn_struct_print_f Provider_reason_print;
asn_constr_check_f Provider_reason_constraint;
ber_type_decoder_f Provider_reason_decode_ber;
der_type_encoder_f Provider_reason_encode_der;
xer_type_decoder_f Provider_reason_decode_xer;
xer_type_encoder_f Provider_reason_encode_xer;
oer_type_decoder_f Provider_reason_decode_oer;
oer_type_encoder_f Provider_reason_encode_oer;
per_type_decoder_f Provider_reason_decode_uper;
per_type_encoder_f Provider_reason_encode_uper;
per_type_decoder_f Provider_reason_decode_aper;
per_type_encoder_f Provider_reason_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Provider_reason_H_ */
#include <asn_internal.h>
