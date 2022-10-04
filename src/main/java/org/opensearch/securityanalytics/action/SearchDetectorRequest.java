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

public class SearchDetectorRequest extends ActionRequest {
    private SearchRequest searchRequest;

    public SearchDetectorRequest(SearchRequest searchRequest) {
        super();
        this.searchRequest = searchRequest;
    }
    public SearchDetectorRequest(StreamInput sin) throws IOException {
        searchRequest = new SearchRequest(sin);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        searchRequest.writeTo(out);
    }

    public SearchRequest searchRequest() {
        return this.searchRequest;
    }
}