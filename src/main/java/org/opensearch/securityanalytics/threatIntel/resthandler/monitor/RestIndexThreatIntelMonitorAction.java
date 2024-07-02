package org.opensearch.securityanalytics.threatIntel.resthandler.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.monitor.IndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.IndexThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.IndexThreatIntelMonitorResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestIndexThreatIntelMonitorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexThreatIntelMonitorAction.class);

    @Override
    public String getName() {
        return "index_threat_intel_monitor_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI),
                new Route(RestRequest.Method.PUT, String.format(Locale.getDefault(), "%s/{%s}",
                        SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, IndexThreatIntelMonitorRequest.THREAT_INTEL_MONITOR_ID))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI));

        String id = request.param(IndexThreatIntelMonitorRequest.THREAT_INTEL_MONITOR_ID, null);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        ThreatIntelMonitorDto iocScanMonitor = ThreatIntelMonitorDto.parse(xcp, id, null);

        IndexThreatIntelMonitorRequest indexThreatIntelMonitorRequest = new IndexThreatIntelMonitorRequest(id, request.method(), iocScanMonitor);
        return channel -> client.execute(IndexThreatIntelMonitorAction.INSTANCE, indexThreatIntelMonitorRequest, getListener(channel, request.method()));
    }

    private RestResponseListener<IndexThreatIntelMonitorResponse> getListener(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexThreatIntelMonitorResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}
