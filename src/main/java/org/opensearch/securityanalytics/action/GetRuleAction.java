/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class GetRuleAction extends ActionType<GetRuleResponse> {

    public static final GetRuleAction INSTANCE = new GetRuleAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/rule/get";

    public GetRuleAction() {
        super(NAME, GetRuleResponse::new);
    }
}
