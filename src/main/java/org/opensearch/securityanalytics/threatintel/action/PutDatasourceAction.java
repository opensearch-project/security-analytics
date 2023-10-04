/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * Threat intel datasource creation action
 */
public class PutDatasourceAction extends ActionType<AcknowledgedResponse> {
    /**
     * Put datasource action instance
     */
    public static final PutDatasourceAction INSTANCE = new PutDatasourceAction();
    /**
     * Put datasource action name
     */
    public static final String NAME = "cluster:admin/security_analytics/datasource/put";

    private PutDatasourceAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
