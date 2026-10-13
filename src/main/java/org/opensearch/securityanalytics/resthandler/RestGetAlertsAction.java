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
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsPageAction;
import org.opensearch.securityanalytics.action.GetAlertsPageRequest;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.transport.client.node.NodeClient;

import static java.util.Collections.singletonList;
import static org.opensearch.action.ValidateActions.addValidationError;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetAlertsAction extends BaseRestHandler {

    /** Opts in to cursor paging: {@code paging=cursor} */
    public static final String PAGING = "paging";
    public static final String CURSOR_PAGING = "cursor";
    /** In cursor paging, the cursor of the alert the page is after (direction next) or before (direction prev) */
    public static final String SEARCH_AFTER = "searchAfter";
    /** In cursor paging, {@code next} (default) or {@code prev} */
    public static final String DIRECTION = "direction";

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

        // paging=cursor: cursor paging, handled by GetAlertsPageAction. The cursor paging params are only read (and so
        // only recognized) with paging, so that requests without it are handled exactly as before.
        String paging = request.param(PAGING);
        if (paging != null) {
            return prepareCursorPagingRequest(request, client, paging, detectorId, detectorType, table, severityLevel, alertState,
                    severityLevels, alertStates, startTime, endTime);
        }

        // The multi value filters are sent as comma separated lists in the single value severityLevel and alertState
        // fields, which keeps GetAlertsRequest's wire format unchanged. They are validated here: a multi value filter
        // with a single value cannot be told apart from the single value filter once in the request.
        ActionRequestValidationException validationException = null;
        if (severityLevels.isEmpty() == false) {
            if (GetAlertsRequest.ALL.equals(severityLevel) == false) {
                validationException = addValidationError("only one of severityLevel and severityLevels can be specified", validationException);
            }
            validationException = GetAlertsRequest.validateSeverityLevels(severityLevels, validationException);
            severityLevel = String.join(GetAlertsRequest.MULTI_VALUE_SEPARATOR, severityLevels);
        }
        if (alertStates.isEmpty() == false) {
            if (GetAlertsRequest.ALL.equals(alertState) == false) {
                validationException = addValidationError("only one of alertState and alertStates can be specified", validationException);
            }
            validationException = GetAlertsRequest.validateAlertStates(alertStates, validationException);
            alertState = String.join(GetAlertsRequest.MULTI_VALUE_SEPARATOR, alertStates);
        }

        GetAlertsRequest req = new GetAlertsRequest(
                detectorId,
                detectorType,
                table,
                severityLevel,
                alertState,
                startTime,
                endTime
        );

        if (validationException != null) {
            // report the request's other validation errors too, as when the request is validated before execution
            ActionRequestValidationException requestValidationException = req.validate();
            if (requestValidationException != null) {
                for (String error : requestValidationException.validationErrors()) {
                    if (validationException.validationErrors().contains(error) == false) {
                        validationException.addValidationError(error);
                    }
                }
            }
            throw validationException;
        }

        return channel -> client.execute(
                GetAlertsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    private RestChannelConsumer prepareCursorPagingRequest(
            RestRequest request,
            NodeClient client,
            String paging,
            String detectorId,
            String detectorType,
            Table table,
            String severityLevel,
            String alertState,
            List<String> severityLevels,
            List<String> alertStates,
            Instant startTime,
            Instant endTime
    ) {
        String searchAfter = request.param(SEARCH_AFTER);
        String directionParam = request.param(DIRECTION);

        ActionRequestValidationException validationException = null;
        if (CURSOR_PAGING.equals(paging) == false) {
            validationException = addValidationError(String.format(Locale.ROOT,
                    "paging [%s] is not supported, supported values are [%s]", paging, CURSOR_PAGING), validationException);
        }
        GetAlertsPageRequest.Direction direction = GetAlertsPageRequest.Direction.NEXT;
        if (directionParam != null) {
            try {
                direction = GetAlertsPageRequest.Direction.parse(directionParam);
            } catch (IllegalArgumentException e) {
                validationException = addValidationError(e.getMessage(), validationException);
            }
        }
        if (searchAfter != null && request.hasParam("startIndex")) {
            validationException = addValidationError("startIndex cannot be used with searchAfter", validationException);
        }

        GetAlertsPageRequest req = new GetAlertsPageRequest(
                detectorId,
                detectorType,
                table,
                severityLevel,
                alertState,
                severityLevels,
                alertStates,
                startTime,
                endTime,
                searchAfter,
                direction
        );
        ActionRequestValidationException requestValidationException = req.validate();
        if (requestValidationException != null) {
            for (String error : requestValidationException.validationErrors()) {
                if (validationException == null || validationException.validationErrors().contains(error) == false) {
                    validationException = addValidationError(error, validationException);
                }
            }
        }
        if (validationException != null) {
            throw validationException;
        }

        return channel -> client.execute(
                GetAlertsPageAction.INSTANCE,
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