/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

public class CreateIndexMappingsAction extends ActionType<AcknowledgedResponse>{

    public static final String NAME = "cluster:admin/opensearch/securityanalytics/mapping/create";
    public static final CreateIndexMappingsAction INSTANCE = new CreateIndexMappingsAction();


    public CreateIndexMappingsAction() {
        super(NAME, AcknowledgedResponse::new);
    }
}
