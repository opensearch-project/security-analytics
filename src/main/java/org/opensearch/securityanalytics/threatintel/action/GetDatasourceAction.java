/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.action.ActionType;

/**
 * Threat intel datasource get action
 */
public class GetDatasourceAction extends ActionType<GetDatasourceResponse> {
    /**
     * Get datasource action instance
     */
    public static final GetDatasourceAction INSTANCE = new GetDatasourceAction();
    /**
     * Get datasource action name
     */
    public static final String NAME = "cluster:admin/security_analytics/datasource/get";

    private GetDatasourceAction() {
        super(NAME, GetDatasourceResponse::new);
    }
}
