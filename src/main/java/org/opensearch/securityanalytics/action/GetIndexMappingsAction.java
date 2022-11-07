/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetIndexMappingsAction extends ActionType<GetIndexMappingsResponse>{

    public static final String NAME = "cluster:admin/opensearch/securityanalytics/mapping/get";
    public static final GetIndexMappingsAction INSTANCE = new GetIndexMappingsAction();


    public GetIndexMappingsAction() {
        super(NAME, GetIndexMappingsResponse::new);
    }
}
