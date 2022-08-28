/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionType;

public class GetMonitorAction extends ActionType<GetMonitorResponse> {
    // Internal Action which is not used for public facing RestAPIs.
    public static final String NAME = "cluster:admin/opendistro/alerting/monitor/get";
    public static final GetMonitorAction INSTANCE = new GetMonitorAction();

    private GetMonitorAction() {
        super(NAME, GetMonitorResponse::new);
    }
}
