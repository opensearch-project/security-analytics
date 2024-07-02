/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetAlertsAction extends ActionType<GetAlertsResponse> {

    public static final GetAlertsAction INSTANCE = new GetAlertsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/alerts/get";

    public GetAlertsAction() {
        super(NAME, GetAlertsResponse::new);
    }
}
