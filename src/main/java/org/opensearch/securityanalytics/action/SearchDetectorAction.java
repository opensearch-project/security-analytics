/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

public class SearchDetectorAction extends ActionType<SearchResponse> {

    public static final SearchDetectorAction INSTANCE = new SearchDetectorAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detector/search";

    public SearchDetectorAction() {
        super(NAME, SearchResponse::new);
    }
}
