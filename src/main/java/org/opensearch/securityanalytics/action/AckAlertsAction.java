/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class AckAlertsAction extends ActionType<AckAlertsResponse> {
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/alerts/ack";
    public static final AckAlertsAction INSTANCE = new AckAlertsAction();

    public AckAlertsAction() {
        super(NAME, AckAlertsResponse::new);
    }
}
