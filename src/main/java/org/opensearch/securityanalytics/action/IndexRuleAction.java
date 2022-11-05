/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class IndexRuleAction extends ActionType<IndexRuleResponse> {

    public static final IndexRuleAction INSTANCE = new IndexRuleAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/rule/write";

    public IndexRuleAction() {
        super(NAME, IndexRuleResponse::new);
    }
}