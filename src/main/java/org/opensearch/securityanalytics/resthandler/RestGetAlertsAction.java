/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.Locale;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetFindingsRequest;
import org.opensearch.securityanalytics.model.Detector;

import static java.util.Collections.singletonList;
import java.util.Arrays;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetAlertsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_alerts_action_sa";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String detectorId = request.param("detector_id", null);
        String[] findingIds = request.paramAsStringArray("findingIds", null);
        String detectorType = request.param("detectorType", null);
        String severityLevel = request.param("severityLevel", "ALL");
        String alertState = request.param("alertState", "ALL");
        // Table params
        String sortString = request.param("sortString", "id");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");

        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );

        GetAlertsRequest req = new GetAlertsRequest(
                detectorId,
                convertFindingIdsToList(findingIds),
                detectorType,
                table,
                severityLevel,
                alertState
        );

        // Request goes to TransportGetAlertsAction class
        return channel -> client.execute(
                GetAlertsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.ALERTS_BASE_URI));
    }

    private ArrayList<String> convertFindingIdsToList(String[] findingIds) {
        if (findingIds == null) {
                return new ArrayList<>();
        }
        return new ArrayList<>(Arrays.asList(findingIds));
    }

}
