package org.opensearch.securityanalytics.threatIntel.sacommons;

import org.opensearch.core.action.ActionListener;
public abstract class TIFSourceConfigManagementService {
    IndexTIFSourceConfigResponse indexTIFConfig(IndexTIFSourceConfigRequest request, ActionListener <IndexTIFSourceConfigResponse> listener){
        return null;
    }

    // TODO:
    // update
    // delete
    // get
}