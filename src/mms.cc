#include "mms.h"
#include "dpx.h"
#include "MmsPdu.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;


void mms_decode(Packet* p, uint8_t *buf, int size){

    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        //printf("        ----mms_decode: dfd empty");
	return;
    }

    MmsPdu_t *mmsPdu = 0;
    asn_dec_rval_t rval;

    rval = ber_decode(0, &asn_DEF_MmsPdu, (void **)&mmsPdu, buf, size);
    if(rval.code == RC_OK){
	//printf("----MMS decode succeed\n");
	
	/*
	int ret = xer_fprint(NULL, &asn_DEF_MmsPdu, mmsPdu);
	if(ret == -1){
	    printf("----MMS xer_fprint failed\n");
	}
	*/
	
	switch(mmsPdu->present){
	    case MmsPdu_PR_confirmedRequestPdu:
	        dfd->mms_session_data.type = 0;
		break;
	    case MmsPdu_PR_confirmedResponsePdu:
                dfd->mms_session_data.type = 1;
		break;
	    case MmsPdu_PR_unconfirmedPDU:
                dfd->mms_session_data.type = 3;
		break;
	    case MmsPdu_PR_initiateRequestPdu:
                dfd->mms_session_data.type = 8;
		break;
	    case MmsPdu_PR_initiateResponsePdu:
                dfd->mms_session_data.type = 9;
		break;
	    case MmsPdu_PR_initiateErrorPdu:
                dfd->mms_session_data.type = 10;
		break;
	    default:
                dfd->mms_session_data.type = 100;
		break;
	}

	//dfd->mms_session_data.type = mmsPdu->present;
	//printf("--------MMS type is %d\n", mmsPdu->present);
        
    }
    else{
	//printf("----MMS decode failed\n");
    }
}
