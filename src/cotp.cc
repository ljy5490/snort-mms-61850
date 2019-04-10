#include "cotp.h"
#include "dpx.h"
#include "iso8327.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;



void cotp_decode(Packet* p, int offset){
    const cotp_header_t* header;
    header = (const cotp_header_t *)(p->data + offset);
    
    //printf("%d", *(p->data));
    //cout << hex << header->code << endl;
    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        //printf("    ----cotp_decode: dfd empty");
        return;
    }
    
    switch(header->code){
        case COTP_CONNECTION_REQUEST:
	    //printf("%s\n", "cotp request found");
	    dfd->reset_mms_session();
	    break;
	case COTP_CONNECTION_CONFIRM:
	    //printf("%s\n", "cotp confrim found");
	    dfd->reset_mms_session();
	    break;
	case COTP_DATA:
    	    {
	        //printf("%s\n", "cotp data found");
		
	        const cotp_data_header_t *data_header;
	        data_header = (const cotp_data_header_t *)(p->data + offset);
	        bool eof = data_header->eof_tpdu_num >> 7;

	        int segment_len = p->dsize - offset - sizeof(cotp_data_header_t);
	        if(eof && dfd->cotp_data.head == NULL){
	            //printf("    ----non-segmented copt data packet, length = %d\n", segment_len);
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
		    //printf("    ----last segmented copt data packet, length = %d\n", dfd->cotp_data.length);
	            iso8327_decode(p, 0);
	            dfd->reset();
	        }
	        else if(dfd->cotp_data.head == NULL){
	            //first segmented copt data packet
	            dfd->cotp_data.length = p->dsize - offset - sizeof(cotp_data_header_t);
	            dfd->cotp_data.head = (uint8_t *)malloc(dfd->cotp_data.length * sizeof(uint8_t));
	            memcpy(dfd->cotp_data.head, p->data+offset+sizeof(cotp_data_header_t), dfd->cotp_data.length);
	            //printf("    ----first segmented copt data packet, length = %d\n", dfd->cotp_data.length);
		    dfd->reset_mms_session();
		}
	        else{
	            //middle segmented copt data packet
	            uint8_t *tmp = dfd->cotp_data.head;
	            dfd->cotp_data.head = (uint8_t *)malloc((dfd->cotp_data.length+segment_len)*sizeof(uint8_t));
	            memcpy(dfd->cotp_data.head, tmp, dfd->cotp_data.length);
	            memcpy(dfd->cotp_data.head + dfd->cotp_data.length, p->data+offset+sizeof(cotp_data_header_t), segment_len);
		    dfd->cotp_data.length += segment_len;
	            free(tmp);
	            //printf("    ----middle segmented copt data packet, length = %d\n", dfd->cotp_data.length);
	            dfd->reset_mms_session();
		}
		
	    }	
	    break;
	default:
	    //printf("%s\n", "unknown cotp code found");
	    dfd->reset_mms_session();
    }
    
    return;
}


