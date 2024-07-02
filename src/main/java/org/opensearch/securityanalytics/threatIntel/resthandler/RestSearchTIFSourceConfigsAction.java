package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SASearchTIFSourceConfigsAction;
import org.opensearch.securityanalytics.threatIntel.action.SASearchTIFSourceConfigsRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static java.util.Collections.singletonList;
import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.rest.RestRequest.Method.POST;

public class RestSearchTIFSourceConfigsAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestSearchTIFSourceConfigsAction.class);

    @Override
    public String getName() {
        return "search_tif_configs_action";
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + "_search"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + "_search"));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        searchSourceBuilder.fetchSource(FetchSourceContext.parseFromRestRequest(request));

        SASearchTIFSourceConfigsRequest req = new SASearchTIFSourceConfigsRequest(searchSourceBuilder);

        return channel -> client.execute(
                SASearchTIFSourceConfigsAction.INSTANCE,
                req,
                new RestSearchTIFSourceConfigResponseListener(channel, request)
        );
    }

    static class RestSearchTIFSourceConfigResponseListener extends RestResponseListener<SearchResponse> {
        private final RestRequest request;

        RestSearchTIFSourceConfigResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final SearchResponse response) throws Exception {
            return new BytesRestResponse(OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }

    }
}
