/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetAlertsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_alerts_action_sa";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String detectorId = request.param("detector_id", null);
        String detectorType = request.param("detectorType", null);
        String severityLevel = request.param("severityLevel", GetAlertsRequest.ALL);
        String alertState = request.param("alertState", GetAlertsRequest.ALL);
        // comma separated multi-value filters, e.g. severityLevels=1,2&alertStates=ACTIVE,ACKNOWLEDGED
        List<String> severityLevels = parseCommaSeparated(request.param("severityLevels"));
        List<String> alertStates = parseCommaSeparated(request.param("alertStates")).stream()
                .map(state -> state.toUpperCase(Locale.ROOT))
                .collect(Collectors.toList());
        // Table params
        String sortString = request.param("sortString", GetAlertsRequest.DEFAULT_SORT_STRING);
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

        GetAlertsRequest req = new GetAlertsRequest(
                detectorId,
                detectorType,
                table,
                severityLevel,
                alertState,
                severityLevels,
                alertStates,
                startTime,
                endTime
        );

        return channel -> client.execute(
                GetAlertsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    private static List<String> parseCommaSeparated(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(v -> v.isEmpty() == false)
                .collect(Collectors.toList());
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.ALERTS_BASE_URI));
    }
}