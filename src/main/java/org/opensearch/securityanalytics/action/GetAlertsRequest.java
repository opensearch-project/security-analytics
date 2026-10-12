/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Table;


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetAlertsRequest extends ActionRequest {

    private String detectorId;
    private String logType;
    private Table table;
    private String severityLevel;
    private String alertState;

    private Instant startTime;

    private Instant endTime;

    public static final String DETECTOR_ID = "detector_id";

    public static final String ALL = "ALL";

    public static final String DEFAULT_SORT_STRING = "start_time";

    /**
     * Alert fields the alerts of all detectors (no detector id and no detector type) can be sorted on: the start time,
     * the detector name (the alert's monitor name, sorted on its keyword sub-field), the status and the severity.
     * <p>
     * The alerts of all detectors may span several log types, whose alert indices are searched separately and whose
     * sorted pages are merged by {@link org.opensearch.securityanalytics.alerts.AlertSorting}, which supports exactly
     * these fields.
     * <p>
     * Requests for a detector id or a detector type are not restricted to these fields: their sort field is passed on
     * to Alerting as is.
     */
    public static final List<String> SORTABLE_FIELDS = List.of(
            "start_time",
            "monitor_name.keyword",
            "state",
            "severity"
    );

    /**
     * Separator of the values of a multi value severityLevel or alertState filter. The REST API's severityLevels and
     * alertStates parameters are sent in the severityLevel and alertState fields as comma separated lists, so that the
     * request's wire format does not change.
     */
    public static final String MULTI_VALUE_SEPARATOR = ",";

    /**
     * {@link Alert.State#AUDIT} alerts are never returned for multiple alert states: the multi value state filter is
     * combined with Alerting's state=ALL filter, which excludes AUDIT alerts.
     */
    public static final List<String> SUPPORTED_ALERT_STATES = Arrays.stream(Alert.State.values())
            .filter(state -> state != Alert.State.AUDIT)
            .map(Enum::name)
            .collect(Collectors.toList());

    /**
     * @param severityLevel a single severity level, ALL, or a comma separated list of severity levels
     * @param alertState a single alert state, ALL, or a comma separated list of alert states
     */
    public GetAlertsRequest(
            String detectorId,
            String logType,
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.detectorId = detectorId;
        this.logType = logType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.startTime = startTime;
        this.endTime = endTime;
    }
    public GetAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readString(),
                sin.readString(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant()
        );
    }

    /**
     * Neither detector id nor log type is required: when both are omitted, alerts of all detectors visible to the
     * caller are returned.
     */
    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        boolean allDetectors = (detectorId == null || detectorId.isEmpty()) && logType == null;
        if (table != null) {
            // Alerts of a detector id or a detector type are sorted by Alerting with a single search, on any field of
            // the alert mapping. Alerts of all detectors may have to be merged across log types, which is supported
            // for the sortable fields only. The check does not depend on the number of log types, so that the same
            // request is not accepted or rejected depending on the detectors that exist.
            if (allDetectors && SORTABLE_FIELDS.contains(table.getSortString()) == false) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "sortString [%s] is not supported, supported values are %s", table.getSortString(), SORTABLE_FIELDS),
                        validationException);
            }
            if ("asc".equalsIgnoreCase(table.getSortOrder()) == false && "desc".equalsIgnoreCase(table.getSortOrder()) == false) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "sortOrder [%s] is not supported, supported values are [asc, desc]", table.getSortOrder()), validationException);
            }
            if (table.getStartIndex() < 0) {
                validationException = addValidationError("startIndex must be greater than or equal to 0", validationException);
            }
            if (table.getSize() < 0) {
                validationException = addValidationError("size must be greater than or equal to 0", validationException);
            }
            String searchStringError = validateSearchString(table.getSearchString());
            if (searchStringError != null) {
                validationException = addValidationError(searchStringError, validationException);
            }
        }
        List<String> severityLevels = getSeverityLevels();
        if (severityLevels.isEmpty() == false) {
            validationException = validateSeverityLevels(severityLevels, validationException);
        }
        List<String> alertStates = getAlertStates();
        if (alertStates.isEmpty() == false) {
            validationException = validateAlertStates(alertStates, validationException);
        }
        return validationException;
    }

    /**
     * Validates the values of a multi value severity level filter: they must not be blank or ALL.
     */
    public static ActionRequestValidationException validateSeverityLevels(List<String> severityLevels,
                                                                          ActionRequestValidationException validationException) {
        if (severityLevels.stream().anyMatch(s -> s == null || s.isBlank() || ALL.equals(s))) {
            validationException = addValidationError(String.format(Locale.ROOT,
                    "severityLevels %s must not contain blank values or [%s]", severityLevels, ALL), validationException);
        }
        return validationException;
    }

    /**
     * Validates the values of a multi value alert state filter: they must be one of {@link #SUPPORTED_ALERT_STATES}.
     */
    public static ActionRequestValidationException validateAlertStates(List<String> alertStates,
                                                                       ActionRequestValidationException validationException) {
        List<String> invalidStates = alertStates.stream().filter(s -> SUPPORTED_ALERT_STATES.contains(s) == false).collect(Collectors.toList());
        if (invalidStates.isEmpty() == false) {
            validationException = addValidationError(String.format(Locale.ROOT,
                    "alertStates %s contains invalid values %s, supported values are %s", alertStates, invalidStates, SUPPORTED_ALERT_STATES),
                    validationException);
        }
        return validationException;
    }

    /**
     * @return the values of a comma separated multi value filter, or an empty list for a single value (or ALL or null)
     */
    static List<String> multiValues(String value) {
        if (value == null || value.contains(MULTI_VALUE_SEPARATOR) == false) {
            return List.of();
        }
        return Arrays.asList(value.split(MULTI_VALUE_SEPARATOR, -1));
    }

    /**
     * The search string is sent to Alerting as a query_string query. Reject syntactically invalid query strings up front
     * (with the same Lucene classic query parser grammar OpenSearch's query_string query is built on) so callers get a
     * 400 instead of a search failure, also when there are no alerts to search.
     */
    private static String validateSearchString(String searchString) {
        if (searchString == null || searchString.isBlank()) {
            return null;
        }
        try (StandardAnalyzer analyzer = new StandardAnalyzer()) {
            QueryParser parser = new QueryParser("monitor_name", analyzer);
            // query_string allows leading wildcards by default
            parser.setAllowLeadingWildcard(true);
            parser.parse(searchString);
            return null;
        } catch (ParseException e) {
            return String.format(Locale.ROOT, "searchString [%s] is not a valid query string: %s", searchString, e.getMessage());
        } catch (RuntimeException e) {
            // e.g. an invalid regular expression (IllegalArgumentException) or one that is too complex to determinize
            // (TooComplexToDeterminizeException), which the search would fail on too
            return String.format(Locale.ROOT, "searchString [%s] is not a valid query string: %s", searchString,
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        out.writeOptionalString(logType);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
    }

    public String getDetectorId() {
        return detectorId;
    }

    public Table getTable() {
        return table;
    }

    public String getSeverityLevel() {
        return severityLevel;
    }

    public String getAlertState() {
        return alertState;
    }

    /**
     * @return the severity levels of a comma separated multi value severityLevel, empty for a single severity level
     */
    public List<String> getSeverityLevels() {
        return multiValues(severityLevel);
    }

    /**
     * @return the alert states of a comma separated multi value alertState, empty for a single alert state
     */
    public List<String> getAlertStates() {
        return multiValues(alertState);
    }

    public String getLogType() {
        return logType;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }
}
