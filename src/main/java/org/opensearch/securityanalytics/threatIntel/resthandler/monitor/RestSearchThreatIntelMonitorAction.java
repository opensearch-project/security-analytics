package org.opensearch.securityanalytics.threatIntel.resthandler.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.monitor.SearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.SearchThreatIntelMonitorRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.core.rest.RestStatus.OK;
import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

public class RestSearchThreatIntelMonitorAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestSearchThreatIntelMonitorAction.class);
    public static final String SEARCH_THREAT_INTEL_MONITOR_PATH = SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + "_search";

    @Override
    public String getName() {
        return "search_threat_intel_monitor_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SEARCH_THREAT_INTEL_MONITOR_PATH));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + "_search"));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        searchSourceBuilder.fetchSource(FetchSourceContext.parseFromRestRequest(request));
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(searchSourceBuilder);
        searchRequest.indices(".opendistro-alerting-config");//todo figure out why it should be mentioned here
        searchRequest.preference(Preference.PRIMARY_FIRST.type());

        BoolQueryBuilder boolQueryBuilder;

        if (searchRequest.source().query() == null) {
            boolQueryBuilder = new BoolQueryBuilder();
        } else {
            boolQueryBuilder = QueryBuilders.boolQuery().must(searchRequest.source().query());
        }

        BoolQueryBuilder bqb = new BoolQueryBuilder();
        bqb.should().add(new BoolQueryBuilder().must(QueryBuilders.matchQuery("monitor.owner", PLUGIN_OWNER_FIELD)));

        boolQueryBuilder.filter(bqb);
        searchRequest.source().query(boolQueryBuilder);

        SearchThreatIntelMonitorRequest searchThreatIntelMonitorRequest = new SearchThreatIntelMonitorRequest(searchRequest);

        return channel -> {
            client.execute(SearchThreatIntelMonitorAction.INSTANCE, searchThreatIntelMonitorRequest, new RestSearchThreatIntelMonitorResponseListener(channel, request));
        };
    }

    static class RestSearchThreatIntelMonitorResponseListener extends RestResponseListener<SearchResponse> {
        private final RestRequest request;

        RestSearchThreatIntelMonitorResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final SearchResponse response) throws Exception {
            return new BytesRestResponse(OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }

    }

}
