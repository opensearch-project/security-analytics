/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;

public class SearchCustomLogTypeAction extends ActionType<SearchResponse> {

    public static final SearchCustomLogTypeAction INSTANCE = new SearchCustomLogTypeAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/logtype/search";

    public SearchCustomLogTypeAction() {
        super(NAME, SearchResponse::new);
    }
}