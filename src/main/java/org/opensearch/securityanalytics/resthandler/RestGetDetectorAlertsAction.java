package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetDetectorAlertsAction;
import org.opensearch.securityanalytics.action.GetDetectorAlertsRequest;
import org.opensearch.securityanalytics.action.GetDetectorAlertsResponse;

import java.io.IOException;
import java.util.List;

public class RestGetDetectorAlertsAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestGetDetectorAlertsAction.class);

    @Override
    public String getName() {
        return "get_alerts_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.GET, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/alerts/{detectorId}")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String detectorId = request.param("detectorId");
        if (detectorId == null || detectorId.isEmpty()) {
            throw new IllegalArgumentException("detector id is missing");
        }
        log.debug("{} {} prepareRequest}",
                RestRequest.Method.GET, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/alerts/" + detectorId);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        String sortString = request.param("sortString", "monitor_name.keyword");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");
        String severityLevel = request.param("severityLevel", "ALL");
        String alertState = request.param("alertState", "ALL");
        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );
        GetDetectorAlertsRequest getDetectorAlertsRequest = new GetDetectorAlertsRequest(
                detectorId, alertState, severityLevel, table);
        return channel -> client.execute(GetDetectorAlertsAction.INSTANCE, getDetectorAlertsRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetDetectorAlertsResponse indexDetectorResponse) {
                        // TODO
                    }

                    @Override
                    public void onFailure(Exception e) {
                        // TODO
                    }
                });
    }
}
