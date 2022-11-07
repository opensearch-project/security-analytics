/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class DeleteRuleAction extends ActionType<DeleteRuleResponse> {

    public static final DeleteRuleAction INSTANCE = new DeleteRuleAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/rule/delete";

    public DeleteRuleAction() {
        super(NAME, DeleteRuleResponse::new);
    }
}