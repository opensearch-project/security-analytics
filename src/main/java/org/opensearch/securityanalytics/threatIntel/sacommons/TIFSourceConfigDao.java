package org.opensearch.securityanalytics.threatIntel.sacommons;

import org.opensearch.core.action.ActionListener;
public interface TIFSourceConfigDao {
    IndexTIFSourceConfigResponse indexTIFConfig(IndexTIFSourceConfigRequest request, ActionListener <IndexTIFSourceConfigResponse> listener);

    // TODO:
    // update
    // delete
    // get
}