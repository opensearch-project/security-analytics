package org.opensearch.securityanalytics.threatIntel.action.monitor.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class SearchThreatIntelMonitorRequest extends ActionRequest {
    private SearchRequest searchRequest;

    public SearchThreatIntelMonitorRequest(SearchRequest searchRequest) {
        super();
        this.searchRequest = searchRequest;
    }

    public SearchThreatIntelMonitorRequest(StreamInput sin) throws IOException {
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
