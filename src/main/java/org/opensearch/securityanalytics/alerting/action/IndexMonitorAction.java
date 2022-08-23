/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.action;

import org.opensearch.action.ActionType;


public class IndexMonitorAction extends ActionType<IndexMonitorResponse> {

    public static final IndexMonitorAction INSTANCE = new IndexMonitorAction();
    public static final String NAME = "cluster:admin/opendistro/security_analytics/monitor/index";

    private IndexMonitorAction() {
        super(NAME, IndexMonitorResponse::new);
    }
}


