#include "acse.h"
#include "dpx.h"
#include "mms.h"

#include "ACSE-apdu.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;

void acse_decode(Packet* p, uint8_t* buf, int size){

    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);
    if(!dfd){
        //printf("        ----acse_decode: dfd empty");
	return;
    }

    ACSE_apdu_t *acsePdu = 0;
    asn_dec_rval_t rval;

    rval = ber_decode(0, &asn_DEF_ACSE_apdu, (void **)&acsePdu, buf, size);
    if(rval.code == RC_OK){
	//printf("----ACSE decode succeed\n");
	
	/*
	int ret = xer_fprint(NULL, &asn_DEF_ACSE_apdu, acsePdu);
	if(ret == -1){
	    printf("----ACSE xer_fprint failed\n");
	}
	*/

	if(acsePdu->present == ACSE_apdu_PR_aarq){
	    if(acsePdu->choice.aarq.user_information != NULL){
	        EXTERNAL **external = (acsePdu->choice.aarq.user_information)->list.array;
                //printf("--------ACSE indirect-reference: %ld\n", *(external[0]->indirect_reference));
	        if(external[0]->encoding.present == EXTERNAL__encoding_PR_single_ASN1_type){
		    int size = (external[0]->encoding).choice.single_ASN1_type.size;
	            uint8_t *buf = (external[0]->encoding).choice.single_ASN1_type.buf;
	            //printf("--------ACSE single asn1 type size: %d\n", size);
		    mms_decode(p, buf, size);
		}
	    }
	}

	if(acsePdu->present == ACSE_apdu_PR_aare){
	    if(acsePdu->choice.aare.user_information != NULL){
	        EXTERNAL **external = (acsePdu->choice.aare.user_information)->list.array;
                //printf("--------ACSE indirect-reference: %ld\n", *(external[0]->indirect_reference));
	        if(external[0]->encoding.present == EXTERNAL__encoding_PR_single_ASN1_type){
		    int size = (external[0]->encoding).choice.single_ASN1_type.size;
	            uint8_t *buf = (external[0]->encoding).choice.single_ASN1_type.buf;
	            //printf("--------ACSE single asn1 type size: %d\n", size);
		    mms_decode(p, buf, size);
		}
	    }
	}
    }
    else{
	//printf("----ACSE decode failed\n");
    }
}


