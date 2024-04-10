/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class SearchCustomLogTypeRequest extends ActionRequest {

    private SearchRequest searchRequest;

    public SearchCustomLogTypeRequest(SearchRequest request) {
        super();
        this.searchRequest = request;
    }

    public SearchCustomLogTypeRequest(StreamInput sin) throws IOException {
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
        return searchRequest;
    }
}