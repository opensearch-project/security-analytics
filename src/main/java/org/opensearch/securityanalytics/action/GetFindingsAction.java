/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetFindingsAction extends ActionType<GetFindingsResponse> {

    public static final GetFindingsAction INSTANCE = new GetFindingsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/findings/get";

    public GetFindingsAction() {
        super(NAME, GetFindingsResponse::new);
    }
}