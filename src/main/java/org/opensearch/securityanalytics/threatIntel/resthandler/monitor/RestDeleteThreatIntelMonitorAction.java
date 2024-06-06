package org.opensearch.securityanalytics.threatIntel.resthandler.monitor;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.monitor.DeleteThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.DeleteThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.IndexThreatIntelMonitorRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.threatIntel.action.monitor.request.IndexThreatIntelMonitorRequest.THREAT_INTEL_MONITOR_ID;

public class RestDeleteThreatIntelMonitorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteThreatIntelMonitorAction.class);

    @Override
    public String getName() {
        return "delete_threat_intel_monitor_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(),
                "%s %s/{%s}",
                request.method(),
                SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI,
                THREAT_INTEL_MONITOR_ID));

        String detectorId = request.param(THREAT_INTEL_MONITOR_ID);
        DeleteThreatIntelMonitorRequest deleteMonitorRequest = new DeleteThreatIntelMonitorRequest(detectorId);
        return channel -> client.execute(
                DeleteThreatIntelMonitorAction.INSTANCE,
                deleteMonitorRequest, new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(),
                        "%s/{%s}",
                        SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI,
                        THREAT_INTEL_MONITOR_ID)));
    }
}