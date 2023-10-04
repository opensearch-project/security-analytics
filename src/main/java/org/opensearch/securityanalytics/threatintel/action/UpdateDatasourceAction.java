/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

/**
 * threat intel datasource update action
 */
public class UpdateDatasourceAction extends ActionType<AcknowledgedResponse> {
    /**
     * Update datasource action instance
     */
    public static final UpdateDatasourceAction INSTANCE = new UpdateDatasourceAction();
    /**
     * Update datasource action name
     */
    public static final String NAME = "cluster:admin/security_analytics/datasource/update";

    private UpdateDatasourceAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
