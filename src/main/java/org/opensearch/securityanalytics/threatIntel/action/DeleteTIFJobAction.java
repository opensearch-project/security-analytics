/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * Threat intel tif job delete action
 */
public class DeleteTIFJobAction extends ActionType<AcknowledgedResponse> {
    /**
     * Delete tif job action instance
     */
    public static final DeleteTIFJobAction INSTANCE = new DeleteTIFJobAction();
    /**
     * Delete tif job action name
     */
    public static final String NAME = "cluster:admin/security_analytics/tifjob/delete";

    private DeleteTIFJobAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
