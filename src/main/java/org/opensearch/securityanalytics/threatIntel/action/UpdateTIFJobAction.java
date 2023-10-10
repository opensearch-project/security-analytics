/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * threat intel tif job update action
 */
public class UpdateTIFJobAction extends ActionType<AcknowledgedResponse> {
    /**
     * Update tif job action instance
     */
    public static final UpdateTIFJobAction INSTANCE = new UpdateTIFJobAction();
    /**
     * Update tif job action name
     */
    public static final String NAME = "cluster:admin/security_analytics/tifjob/update";

    private UpdateTIFJobAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
