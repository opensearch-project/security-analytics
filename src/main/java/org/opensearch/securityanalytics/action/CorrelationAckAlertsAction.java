/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Acknowledge Alert Action
 */
public class CorrelationAckAlertsAction extends ActionType<CorrelationAckAlertsResponse> {
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/correlationAlerts/ack";
    public static final CorrelationAckAlertsAction INSTANCE = new CorrelationAckAlertsAction();

    public CorrelationAckAlertsAction() {
        super(NAME, CorrelationAckAlertsResponse::new);
    }
}

