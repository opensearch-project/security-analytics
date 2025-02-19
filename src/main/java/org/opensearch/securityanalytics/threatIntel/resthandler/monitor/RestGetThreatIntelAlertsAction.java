package org.opensearch.securityanalytics.threatIntel.resthandler.monitor;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;

import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.monitor.GetThreatIntelAlertsAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.GetThreatIntelAlertsRequest;


import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetThreatIntelAlertsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_threat_intel_alerts_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String severityLevel = request.param("severityLevel", "ALL");
        String alertState = request.param("alertState", "ALL");
        // Table params
        String sortString = request.param("sortString", "start_time");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");

        Instant startTime = null;
        String startTimeParam = request.param("startTime");
        if (startTimeParam != null && !startTimeParam.isEmpty()) {
            try {
                startTime = Instant.ofEpochMilli(Long.parseLong(startTimeParam));
            } catch (NumberFormatException | NullPointerException | DateTimeException e) {
                startTime = Instant.now();
            }
        }

        Instant endTime = null;
        String endTimeParam = request.param("endTime");
        if (endTimeParam != null && !endTimeParam.isEmpty()) {
            try {
                endTime = Instant.ofEpochMilli(Long.parseLong(endTimeParam));
            } catch (NumberFormatException | NullPointerException | DateTimeException e) {
                endTime = Instant.now();
            }
        }

        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );

        GetThreatIntelAlertsRequest req = new GetThreatIntelAlertsRequest(
                table,
                severityLevel,
                alertState,
                startTime,
                endTime
        );

        return channel -> client.execute(
                GetThreatIntelAlertsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_URI));
    }
}