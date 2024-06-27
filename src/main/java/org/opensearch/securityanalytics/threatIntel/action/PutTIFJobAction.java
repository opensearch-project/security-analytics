/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * Threat intel tif job creation action
 */
public class PutTIFJobAction extends ActionType<AcknowledgedResponse> {
    /**
     * Put tif job action instance
     */
    public static final PutTIFJobAction INSTANCE = new PutTIFJobAction();
    /**
     * Put tif job action name
     */
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/tifjob/put";

    private PutTIFJobAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
