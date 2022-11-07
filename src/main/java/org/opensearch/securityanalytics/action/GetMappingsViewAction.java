/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetMappingsViewAction extends ActionType<GetMappingsViewResponse>{

    public static final String NAME = "cluster:admin/opensearch/securityanalytics/mapping/view/get";
    public static final GetMappingsViewAction INSTANCE = new GetMappingsViewAction();


    public GetMappingsViewAction() {
        super(NAME, GetMappingsViewResponse::new);
    }
}
