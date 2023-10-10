/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

/**
 * Threat intel tif job get action
 */
public class GetTIFJobAction extends ActionType<GetTIFJobResponse> {
    /**
     * Get tif job action instance
     */
    public static final GetTIFJobAction INSTANCE = new GetTIFJobAction();
    /**
     * Get tif job action name
     */
    public static final String NAME = "cluster:admin/security_analytics/tifjob/get";

    private GetTIFJobAction() {
        super(NAME, GetTIFJobResponse::new);
    }
}
