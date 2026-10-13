/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

/**
 * Gets a page of alerts with cursor paging: GET _plugins/_security_analytics/alerts with {@code paging=cursor}. Requests
 * without {@code paging} are handled by {@link GetAlertsAction}, as before.
 */
public class GetAlertsPageAction extends ActionType<GetAlertsPageResponse> {

    public static final GetAlertsPageAction INSTANCE = new GetAlertsPageAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/alerts/get_page";

    public GetAlertsPageAction() {
        super(NAME, GetAlertsPageResponse::new);
    }
}
