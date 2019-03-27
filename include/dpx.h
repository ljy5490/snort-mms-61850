#ifndef DPX_H
#define DPX_H

#include "flow/flow.h"

struct cotp_segment_data_t{
    bool seg_or_not = false;
    uint8_t *head = NULL;
    int length = 0;
};

struct mms_session_data_t{
    uint8_t type = 100;
};

class DpxFlowData : public snort::FlowData{
    public:
        DpxFlowData();
	~DpxFlowData() override;

	static void init();

	void reset(){
	    cotp_data.seg_or_not = false;
	    cotp_data.length = 0;
            if(cotp_data.head != NULL)
	        free(cotp_data.head);
	    cotp_data.head = NULL;
	}

	void reset_mms_session(){
	    mms_session_data.type = 100;
	}

    public:
	static unsigned inspector_id;
	cotp_segment_data_t cotp_data;
	mms_session_data_t mms_session_data;
};

#endif
