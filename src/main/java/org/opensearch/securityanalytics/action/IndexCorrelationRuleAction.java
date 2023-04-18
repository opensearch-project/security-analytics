/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class IndexCorrelationRuleAction extends ActionType<IndexCorrelationRuleResponse> {

    public static final IndexCorrelationRuleAction INSTANCE = new IndexCorrelationRuleAction();
    public static final String NAME = "cluster:admin/index/correlation/rules/create";

    private IndexCorrelationRuleAction() {
        super(NAME, IndexCorrelationRuleResponse::new);
    }
}
