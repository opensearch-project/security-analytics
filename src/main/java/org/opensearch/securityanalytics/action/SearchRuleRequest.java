/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;

import java.io.IOException;

public class SearchRuleRequest extends ActionRequest {

    /**
     * this param decides whether search will be done on pre-packaged rules or custom rules.
     */
    private Boolean isPrepackaged;

    private SearchRequest searchRequest;

    public SearchRuleRequest(Boolean isPrepackaged, SearchRequest searchRequest) {
        super();
        this.isPrepackaged = isPrepackaged;
        this.searchRequest = searchRequest;
    }

    public SearchRuleRequest(StreamInput sin) throws IOException {
        this(sin.readBoolean(),
             new SearchRequest(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(isPrepackaged);
        searchRequest.writeTo(out);
    }

    public Boolean isPrepackaged() {
        return isPrepackaged;
    }

    public SearchRequest getSearchRequest() {
        return searchRequest;
    }
}