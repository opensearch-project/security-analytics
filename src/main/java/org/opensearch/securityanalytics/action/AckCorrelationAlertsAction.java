/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Acknowledge Correlation Alert Action
 */
public class AckCorrelationAlertsAction extends ActionType<AckCorrelationAlertsResponse> {
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/correlationAlerts/ack";
    public static final AckCorrelationAlertsAction INSTANCE = new AckCorrelationAlertsAction();

    public AckCorrelationAlertsAction() {
        super(NAME, AckCorrelationAlertsResponse::new);
    }
}

