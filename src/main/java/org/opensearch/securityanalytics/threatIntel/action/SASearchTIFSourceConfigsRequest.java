/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.io.IOException;

/**
 * Search threat intel feed source config request
 */
public class SASearchTIFSourceConfigsRequest extends ActionRequest {

    // TODO: add pagination parameters
    private final SearchSourceBuilder searchSourceBuilder;

    public SASearchTIFSourceConfigsRequest(SearchSourceBuilder searchSourceBuilder) {
        super();
        this.searchSourceBuilder = searchSourceBuilder;
    }

    public SASearchTIFSourceConfigsRequest(StreamInput sin) throws IOException {
        searchSourceBuilder = new SearchSourceBuilder(sin);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        searchSourceBuilder.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public SearchSourceBuilder getSearchSourceBuilder() {
        return searchSourceBuilder;
    }

}
