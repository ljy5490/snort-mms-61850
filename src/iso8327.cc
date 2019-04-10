#include "iso8327.h"
#include "dpx.h"
#include "iso8823.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;

void iso8327_decode(Packet* p, int offset){
    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        //printf("        ----iso8327_decode: dfd empty");
	return;
    }

    const uint8_t *tmp;
    const iso8327_header_t* header;

    if(dfd->cotp_data.head == NULL){
        header = (const iso8327_header_t *)(p->data + offset);
	tmp = p->data;
    }
    else{
	header = (const iso8327_header_t *)(dfd->cotp_data.head);
	tmp = dfd->cotp_data.head;
    }

    int type;

    switch(header->id){
	case ISO8327_SPDU_CONNECT:
	case ISO8327_SPDU_ACCEPT:
	    {
		const spdu_parameter_header_t* param_header;
	        int processed_param_len = 0;
		bool type_139 = false;
	        while(processed_param_len < header->len){
		    param_header = (const spdu_parameter_header_t *)(tmp + offset + 2 + processed_param_len);
		    if(param_header->type == 193){
			offset = offset + 2 + processed_param_len + 2;
			if(header->id == ISO8327_SPDU_CONNECT)
			    iso8823_decode(p, offset, ISO8823_CP_TYPE);
			else
	                    iso8823_decode(p, offset, ISO8823_CPA_PPDU);
			
			type_139 = true;
			break;
		    }
		    else{
		        processed_param_len += 2 + param_header->len;
		    }
		}
		if(!type_139)
	            //printf("iso8327: SPDU Parameter type 139 not found\n");
		    ;
	    }
	    break;
	case ISO8327_SPDU_DATA_GIVE_TOKENS:
	    {
	        if(header->len != 0){
	            //printf("iso8327: SPDU Given Token ID length not equal to 0\n");
	        }
	        const iso8327_header_t* second_header;
		if(dfd->cotp_data.head == NULL)
	            second_header = (const iso8327_header_t *)(p->data + offset + 2 + header->len);
		else
		    second_header = (const iso8327_header_t *)(dfd->cotp_data.head + 2 + header->len);

	        if(second_header->id != ISO8327_SPDU_DATA_TRANSFER)
	            printf("iso8327: Second ISO8327 ID is not DATA_TRANSFER\n");
	        if(second_header->len != 0){
	            //printf("iso8327: Second SPDU len != 0\n");
	        }
	        offset = offset + 2 + header->len + 2 + second_header->len;
	        iso8823_decode(p, offset, ISO8823_CPC_TYPE);
	    }
	        break;
	default:
	    //printf("iso8327: Unknown SPDU ID found\n");
	    ;
    }
}
