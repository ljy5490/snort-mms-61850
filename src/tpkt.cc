#include "tpkt.h"
#include "dpx.h"

#include "CP-type.h"
#include "CPA-PPDU.h"
#include "CPC-type.h"

#include "MmsPdu.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;

#define TPKT_VERSION 0x03
#define TPKT_RESERVED 0x00

#define COTP_CONNECTION_REQUEST 0xe0
#define COTP_CONNECTION_CONFIRM 0xd0
#define COTP_DATA 0xf0

#define ISO8327_SPDU_CONNECT 0x0d
#define ISO8327_SPDU_ACCEPT 0x0e
#define ISO8327_SPDU_DATA_GIVE_TOKENS 0x01
#define ISO8327_SPDU_DATA_TRANSFER 0x01

#define ISO8823_CP_TYPE 0x01
#define ISO8823_CPA_PPDU 0x02
#define ISO8823_CPC_TYPE 0x03


struct tpkt_header_t{
    uint8_t version;
    uint8_t reserved;
    uint8_t length1;
    uint8_t length2;
};

struct cotp_header_t{
    uint8_t header_len;
    uint8_t code;
};

struct cotp_data_header_t{
    uint8_t header_len;
    uint8_t code;
    uint8_t eof_tpdu_num;
};

struct iso8327_header_t{
    uint8_t id;
    uint8_t len;
};

struct spdu_parameter_header_t{
    uint8_t type;
    uint8_t len;
};

void mms_decode(uint8_t *buf, int size){
    MmsPdu_t *mmsPdu = 0;
    asn_dec_rval_t rval;

    rval = ber_decode(0, &asn_DEF_MmsPdu, (void **)&mmsPdu, buf, size);
    if(rval.code == RC_OK){
	printf("----MMS decode succeed\n");
	int ret = xer_fprint(NULL, &asn_DEF_MmsPdu, mmsPdu);
	if(ret == -1){
	    printf("----MMS xer_fprint failed\n");
	}
    }
    else{
	printf("----MMS decode failed\n");
    }
}

void iso8823_decode(Packet* p, int offset, int type){
    
    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        printf("        ----iso8823_decode: dfd empty");
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
		    printf("iso8823: CP-type decode succeed\n");
		    int ret = xer_fprint(NULL, &asn_DEF_CP_type, cp_type);
		}
		else{
		    printf("iso8823: CP-type decode failed\n");
		}
	    }
	    break;
	case ISO8823_CPA_PPDU:
	    {
		CPA_PPDU_t *cpa_ppdu = 0;
		rval = ber_decode(0, &asn_DEF_CPA_PPDU, (void **)&cpa_ppdu, head, len);
	        if(rval.code == RC_OK){
	    	    printf("iso8823: CPA-PPDU decode succeed\n");
		    int ret = xer_fprint(NULL, &asn_DEF_CPA_PPDU, cpa_ppdu);
	    	}
	    	else{
	    	    printf("iso8823: CPA-PPDU decode failed\n");
	    	}
	    }
	    break;
	case ISO8823_CPC_TYPE:
	    {
		CPC_type_t *cpc_type = 0;
		rval = ber_decode(0, &asn_DEF_CPC_type, (void **)&cpc_type, head, len);
	        if(rval.code == RC_OK){
	    	    printf("iso8823: CPC-type decode succeed\n");
		    //int ret = xer_fprint(NULL, &asn_DEF_CPC_type, cpc_type);
		    if(cpc_type->present == User_data_PR_fully_encoded_data){
			PDV_list **pdv_list = (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).array;
			printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).count);
			printf("----fully_encoded_data: %d\n", (((Fully_encoded_data_t)cpc_type->choice.fully_encoded_data).list).size);
			printf("----presentation-context-identifier: %lu\n", pdv_list[0]->presentation_context_identifier);

			printf("----single_ASN1_type size: %d\n", (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size);
			int size = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.size;
			uint8_t *buf = (pdv_list[0]->presentation_data_values).choice.single_ASN1_type.buf;
			mms_decode(buf, size);
		    }
	    	}
	    	else{
	    	    printf("iso8823: CPC-type decode failed\n");
	    	}
	    }
	    break;
	default:
	    printf("iso8823: not supported type found\n");
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


void iso8327_decode(Packet* p, int offset){
    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        printf("        ----iso8327_decode: dfd empty");
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
	            printf("iso8327: SPDU Parameter type 139 not found\n");
	    }
	    break;
	case ISO8327_SPDU_DATA_GIVE_TOKENS:
	    {
	        if(header->len != 0){
	            printf("iso8327: SPDU Given Token ID length not equal to 0\n");
	        }
	        const iso8327_header_t* second_header;
		if(dfd->cotp_data.head == NULL)
	            second_header = (const iso8327_header_t *)(p->data + offset + 2 + header->len);
		else
		    second_header = (const iso8327_header_t *)(dfd->cotp_data.head + 2 + header->len);

	        if(second_header->id != ISO8327_SPDU_DATA_TRANSFER)
	            printf("iso8327: Second ISO8327 ID is not DATA_TRANSFER\n");
	        if(second_header->len != 0){
	            printf("iso8327: Second SPDU len != 0\n");
	        }
	        offset = offset + 2 + header->len + 2 + second_header->len;
	        iso8823_decode(p, offset, ISO8823_CPC_TYPE);
	    }
	        break;
	default:
	    printf("iso8327: Unknown SPDU ID found\n");
    }
}


void cotp_decode(Packet* p, int offset){
    const cotp_header_t* header;
    header = (const cotp_header_t *)(p->data + offset);
    
    //printf("%d", *(p->data));
    //cout << hex << header->code << endl;
    
    switch(header->code){
        case COTP_CONNECTION_REQUEST:
	    printf("%s\n", "cotp request found");
	    break;
	case COTP_CONNECTION_CONFIRM:
	    printf("%s\n", "cotp confrim found");
	    break;
	case COTP_DATA:
    	    {
	        printf("%s\n", "cotp data found");
		
	        const cotp_data_header_t *data_header;
	        data_header = (const cotp_data_header_t *)(p->data + offset);
	        bool eof = data_header->eof_tpdu_num >> 7;
	        DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
	        if(!dfd){
	            printf("    ----cotp_decode: dfd empty");
	            return;
	        }

	        int segment_len = p->dsize - offset - sizeof(cotp_data_header_t);
	        if(eof && dfd->cotp_data.head == NULL){
	            printf("    ----non-segmented copt data packet, length = %d\n", segment_len);
		    iso8327_decode(p, offset+sizeof(cotp_data_header_t));
	        }
	        else if(eof){
	            //last segmented copt data packet
	            uint8_t *tmp = dfd->cotp_data.head;
	            dfd->cotp_data.head = (uint8_t *)malloc((dfd->cotp_data.length+segment_len)*sizeof(uint8_t));
	            memcpy(dfd->cotp_data.head, tmp, dfd->cotp_data.length);
	            memcpy(dfd->cotp_data.head + dfd->cotp_data.length, p->data+offset+sizeof(cotp_data_header_t), segment_len);
		    dfd->cotp_data.length += segment_len;
	            free(tmp);
		    printf("    ----last segmented copt data packet, length = %d\n", dfd->cotp_data.length);
	            iso8327_decode(p, 0);
	            dfd->reset();
	        }
	        else if(dfd->cotp_data.head == NULL){
	            //first segmented copt data packet
	            dfd->cotp_data.length = p->dsize - offset - sizeof(cotp_data_header_t);
	            dfd->cotp_data.head = (uint8_t *)malloc(dfd->cotp_data.length * sizeof(uint8_t));
	            memcpy(dfd->cotp_data.head, p->data+offset+sizeof(cotp_data_header_t), dfd->cotp_data.length);
	            printf("    ----first segmented copt data packet, length = %d\n", dfd->cotp_data.length);
		}
	        else{
	            //middle segmented copt data packet
	            uint8_t *tmp = dfd->cotp_data.head;
	            dfd->cotp_data.head = (uint8_t *)malloc((dfd->cotp_data.length+segment_len)*sizeof(uint8_t));
	            memcpy(dfd->cotp_data.head, tmp, dfd->cotp_data.length);
	            memcpy(dfd->cotp_data.head + dfd->cotp_data.length, p->data+offset+sizeof(cotp_data_header_t), segment_len);
		    dfd->cotp_data.length += segment_len;
	            free(tmp);
	            printf("    ----middle segmented copt data packet, length = %d\n", dfd->cotp_data.length);
	        }
		
	    }	
	    break;
	default:
	    printf("%s\n", "unknown cotp code found");
    }
    
    return;
}


void tpkt_decode(Packet *p){
    const tpkt_header_t *header;
    header = (const tpkt_header_t *)p->data;

    if(header->version != TPKT_VERSION){
	//DetectionEngine::queue_event()
        printf("TPKT:bad version number");
    }

    if(header->reserved != TPKT_RESERVED){
	//DetectionEngine::queue_event()
        printf("TPKT:bad reserved");
    }

    cotp_decode(p, 4);
    //printf("%d %d\n", header->length1, header->length2);
    return;
}
