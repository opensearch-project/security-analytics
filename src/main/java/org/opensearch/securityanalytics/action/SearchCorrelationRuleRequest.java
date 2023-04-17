/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

public class SearchCorrelationRuleRequest extends ActionRequest {

    /**
     * this param decides whether search will be done on pre-packaged rules or custom rules.
     */

    private SearchRequest searchRequest;

    public SearchCorrelationRuleRequest(SearchRequest searchRequest) {
        super();
        this.searchRequest = searchRequest;
    }

    public SearchCorrelationRuleRequest(StreamInput sin) throws IOException {
        this(new SearchRequest(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        searchRequest.writeTo(out);
    }

    public SearchRequest getSearchRequest() {
        return searchRequest;
    }
}