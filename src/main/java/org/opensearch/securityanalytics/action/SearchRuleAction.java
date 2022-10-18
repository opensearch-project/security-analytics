/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

public class SearchRuleAction extends ActionType<SearchResponse> {

    public static final SearchRuleAction INSTANCE = new SearchRuleAction();
    public static final String NAME = "cluster:admin/opendistro/securityanalytics/rule/search";

    public SearchRuleAction() {
        super(NAME, SearchResponse::new);
    }
}