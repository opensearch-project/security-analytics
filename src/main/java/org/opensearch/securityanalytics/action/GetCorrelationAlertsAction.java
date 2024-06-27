/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetCorrelationAlertsAction extends ActionType<GetCorrelationAlertsResponse> {

    public static final GetCorrelationAlertsAction INSTANCE = new GetCorrelationAlertsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/correlationAlerts/get";

    public GetCorrelationAlertsAction() {
        super(NAME, GetCorrelationAlertsResponse::new);
    }
}