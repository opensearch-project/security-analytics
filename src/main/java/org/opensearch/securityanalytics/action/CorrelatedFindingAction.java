/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class CorrelatedFindingAction extends ActionType<CorrelatedFindingResponse> {
    public static final CorrelatedFindingAction INSTANCE = new CorrelatedFindingAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/findings/correlated";

    public CorrelatedFindingAction() {
        super(NAME, CorrelatedFindingResponse::new);
    }
}