/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.action;

import org.opensearch.action.ActionType;

public class ExecuteMonitorAction extends ActionType<ExecuteMonitorResponse> {

    public static final String NAME = "cluster:admin/opendistro/security_analytics/monitor/execute";
    public static final ExecuteMonitorAction INSTANCE = new ExecuteMonitorAction();

    private ExecuteMonitorAction() {
        super(NAME, ExecuteMonitorResponse::new);
    }
}



