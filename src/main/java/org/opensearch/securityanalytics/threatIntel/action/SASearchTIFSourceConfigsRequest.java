/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Search threat intel feed source config request
 */
public class SASearchTIFSourceConfigsRequest extends ActionRequest {
    private SearchRequest searchRequest;

    public SASearchTIFSourceConfigsRequest(SearchRequest searchRequest) {
        super();
        this.searchRequest = searchRequest;
    }

    public SASearchTIFSourceConfigsRequest(StreamInput sin) throws IOException {
        searchRequest = new SearchRequest(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        searchRequest.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public SearchRequest getSearchRequest() {
        return searchRequest;
    }

}
