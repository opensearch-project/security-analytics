/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

public class SearchCorrelationRuleAction extends ActionType<SearchResponse> {

    public static final SearchCorrelationRuleAction INSTANCE = new SearchCorrelationRuleAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/correlation/rule/search";

    public SearchCorrelationRuleAction() {
        super(NAME, SearchResponse::new);
    }
}