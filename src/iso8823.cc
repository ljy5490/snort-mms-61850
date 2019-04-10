#include "iso8823.h"
#include "dpx.h"
#include "acse.h"
#include "mms.h"

#include "CP-type.h"
#include "CPA-PPDU.h"
#include "CPC-type.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;

void iso8823_decode(Packet* p, int offset, int type){
    
    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        //printf("        ----iso8823_decode: dfd empty");
	return;
    }
    
    uint8_t* head;
    int len;

    if(dfd->cotp_data.head == NULL){
        head = (uint8_t *)(p->data + offset);
	len = p->dsize - offset;
    }
    else{
	head = (uint8_t *)(dfd->cotp_data.head + offset);
	len = dfd->cotp_data.length - offset;
    }

    asn_dec_rval_t rval;
    switch(type){
	case ISO8823_CP_TYPE:
	    {
		CP_type_t *cp_type = 0;
		rval = ber_decode(0, &asn_DEF_CP_type, (void **)&cp_type, head, len);
	        if(rval.code == RC_OK){
		    //printf("iso8823: CP-type decode succeed\n");
		    //int ret = xer_fprint(NULL, &asn_DEF_CP_type, cp_type);
		    if(cp_type->normal_mode_parameters != NULL){
			if(cp_type->normal_mode_parameters->user_data != NULL){
			    User_data *user_data = cp_type->normal_mode_parameters->user_data;
			    if(user_data->present == User_data_PR_fully_encoded_data){
                                PDV_list **pdv_list = (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).array;
			        //printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).count);
			        //printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).size);
			        //printf("----presentation-context-identifier: %lu\n", pdv_list[0]->presentation_context_identifier);

			        //printf("----single_ASN1_type size: %d\n", (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size);
			        int size = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size;
			        uint8_t *buf = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.buf;
			        acse_decode(p, buf, size);
			    }
			}
		    }
		}
		else{
		    //printf("iso8823: CP-type decode failed\n");
		}
	    }
	    break;
	case ISO8823_CPA_PPDU:
	    {
		CPA_PPDU_t *cpa_ppdu = 0;
		rval = ber_decode(0, &asn_DEF_CPA_PPDU, (void **)&cpa_ppdu, head, len);
	        if(rval.code == RC_OK){
	    	    //printf("iso8823: CPA-PPDU decode succeed\n");
		    //int ret = xer_fprint(NULL, &asn_DEF_CPA_PPDU, cpa_ppdu);
	    	    if(cpa_ppdu->normal_mode_parameters != NULL){
			if(cpa_ppdu->normal_mode_parameters->user_data != NULL){
			    User_data *user_data = cpa_ppdu->normal_mode_parameters->user_data;
			    if(user_data->present == User_data_PR_fully_encoded_data){
                                PDV_list **pdv_list = (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).array;
			        //printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).count);
			        //printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)user_data->choice.fully_encoded_data).list).size);
			        //printf("----presentation-context-identifier: %lu\n", pdv_list[0]->presentation_context_identifier);

			        //printf("----single_ASN1_type size: %d\n", (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size);
			        int size = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size;
			        uint8_t *buf = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.buf;
			        acse_decode(p, buf, size);
			    }
			}
		    }
		}
	    	else{
	    	    //printf("iso8823: CPA-PPDU decode failed\n");
	    	}
	    }
	    break;
	case ISO8823_CPC_TYPE:
	    {
		CPC_type_t *cpc_type = 0;
		rval = ber_decode(0, &asn_DEF_CPC_type, (void **)&cpc_type, head, len);
	        if(rval.code == RC_OK){
	    	    //printf("iso8823: CPC-type decode succeed\n");
		    //int ret = xer_fprint(NULL, &asn_DEF_CPC_type, cpc_type);
		    if(cpc_type->present == User_data_PR_fully_encoded_data){
			PDV_list **pdv_list = (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).array;
			//printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).count);
			//printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).size);
			//printf("----presentation-context-identifier: %lu\n", pdv_list[0]->presentation_context_identifier);

			//printf("----single_ASN1_type size: %d\n", (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size);
			int size = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size;
			uint8_t *buf = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.buf;
			mms_decode(p, buf, size);
		    }
	    	}
	    	else{
	    	    //printf("iso8823: CPC-type decode failed\n");
	    	}
	    }
	    break;
	default:
	    //printf("iso8823: not supported type found\n");
	    ;
    }
    /*
    for(int i=1; i<=len; i++){
	printf("%X ", head[i-1]);
	if(i % 8 == 0)
	    printf("\n");
    }
    */

    return;
}


