/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionType;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;

public class GetIndexMappingsAction extends ActionType<GetIndexMappingsResponse>{

    public static final String NAME = "cluster:admin/opendistro/securityanalytics/mapping/get";
    public static final GetIndexMappingsAction INSTANCE = new GetIndexMappingsAction();


    public GetIndexMappingsAction() {
        super(NAME, GetIndexMappingsResponse::new);
    }
}
