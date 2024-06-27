/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionType;

public class GetIocFindingsAction extends ActionType<GetIocFindingsResponse> {

    public static final GetIocFindingsAction INSTANCE = new GetIocFindingsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/threatintel/iocs/findings/get";

    public GetIocFindingsAction() {
        super(NAME, GetIocFindingsResponse::new);
    }
}