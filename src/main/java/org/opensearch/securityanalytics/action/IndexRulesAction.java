/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class IndexRulesAction extends ActionType<IndexRulesResponse> {

    public static final IndexRulesAction INSTANCE = new IndexRulesAction();
    public static final String NAME = "cluster:admin/opendistro/securityanalytics/rules/write";

    public IndexRulesAction() {
        super(NAME, IndexRulesResponse::new);
    }
}