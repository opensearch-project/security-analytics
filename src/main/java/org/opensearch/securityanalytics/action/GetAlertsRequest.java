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
import org.opensearch.Version;
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
    private List<String> severityLevels;
    private List<String> alertStates;

    private Instant startTime;

    private Instant endTime;

    public static final String DETECTOR_ID = "detector_id";

    public static final String ALL = "ALL";

    public static final String DEFAULT_SORT_STRING = "start_time";

    /**
     * Alert fields the alerts of all detectors (no detector id and no detector type) can be sorted on.
     * <p>
     * These are the fields of Alerting's alert mapping (alert_mapping.json) that OpenSearch can sort on and whose
     * values are available on the parsed {@link Alert}, so that pages fetched per log type can be merged with the
     * same order (see {@link org.opensearch.securityanalytics.alerts.AlertSorting}). Not included are text fields
     * (e.g. monitor_name, use monitor_name.keyword), nested and object fields (alert_history, action_execution_results,
     * query_results, agg_alert_content, monitor_user) and the id and version fields, whose stored values differ from
     * the alert's id and version (those are the document's _id and _version).
     * <p>
     * Requests for a detector id or a detector type are not restricted to these fields: their sort field is passed on
     * to Alerting as is.
     */
    public static final List<String> SORTABLE_FIELDS = List.of(
            // dates
            "start_time",
            "last_notification_time",
            "end_time",
            "acknowledged_time",
            // keywords
            "monitor_id",
            "trigger_id",
            "execution_id",
            "workflow_id",
            "workflow_name",
            "severity",
            "state",
            // keyword sub-fields of text fields
            "monitor_name.keyword",
            "trigger_name.keyword",
            "finding_ids.keyword",
            "related_doc_ids.keyword",
            "associated_alert_ids.keyword",
            "clusters.keyword",
            // numerics
            "schema_version",
            "monitor_version"
    );

    public GetAlertsRequest(
            String detectorId,
            String logType,
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        this(detectorId, logType, table, severityLevel, alertState, List.of(), List.of(), startTime, endTime);
    }

    public GetAlertsRequest(
            String detectorId,
            String logType,
            Table table,
            String severityLevel,
            String alertState,
            List<String> severityLevels,
            List<String> alertStates,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.detectorId = detectorId;
        this.logType = logType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.severityLevels = severityLevels != null ? severityLevels : List.of();
        this.alertStates = alertStates != null ? alertStates : List.of();
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public GetAlertsRequest(StreamInput sin) throws IOException {
        this.detectorId = sin.readOptionalString();
        this.logType = sin.readOptionalString();
        this.table = Table.readFrom(sin);
        this.severityLevel = sin.readString();
        this.alertState = sin.readString();
        this.startTime = sin.readOptionalInstant();
        this.endTime = sin.readOptionalInstant();
        if (sin.getVersion().onOrAfter(Version.V_3_10_0)) {
            this.severityLevels = sin.readStringList();
            this.alertStates = sin.readStringList();
        } else {
            this.severityLevels = List.of();
            this.alertStates = List.of();
        }
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
        if (severityLevels.isEmpty() == false) {
            if (severityLevel != null && ALL.equals(severityLevel) == false) {
                validationException = addValidationError("only one of severityLevel and severityLevels can be specified", validationException);
            }
            if (severityLevels.stream().anyMatch(s -> s == null || s.isBlank() || ALL.equals(s))) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "severityLevels %s must not contain blank values or [%s]", severityLevels, ALL), validationException);
            }
        }
        if (alertStates.isEmpty() == false) {
            if (alertState != null && ALL.equals(alertState) == false) {
                validationException = addValidationError("only one of alertState and alertStates can be specified", validationException);
            }
            List<String> validStates = Arrays.stream(Alert.State.values()).map(Enum::name).collect(Collectors.toList());
            List<String> invalidStates = alertStates.stream().filter(s -> validStates.contains(s) == false).collect(Collectors.toList());
            if (invalidStates.isEmpty() == false) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "alertStates %s contains invalid values %s, supported values are %s", alertStates, invalidStates, validStates),
                        validationException);
            }
        }
        return validationException;
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
        if (out.getVersion().onOrAfter(Version.V_3_10_0)) {
            out.writeStringCollection(severityLevels);
            out.writeStringCollection(alertStates);
        }
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

    public List<String> getSeverityLevels() {
        return severityLevels;
    }

    public List<String> getAlertStates() {
        return alertStates;
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
