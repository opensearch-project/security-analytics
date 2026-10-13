/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.securityanalytics.alerts.AlertsCursor;

import static org.opensearch.action.ValidateActions.addValidationError;

/**
 * A page of alerts in cursor paging (the REST API's {@code paging=cursor}), see {@link GetAlertsPageAction}.
 * <p>
 * The page is either at an offset (no cursor: {@code startIndex}, within the max result window like
 * {@link GetAlertsRequest}) or right after or before the alert of a cursor ({@code searchAfter} with the direction
 * {@code next} or {@code prev}), which reaches alerts beyond the max result window. Alerts are always found with a
 * single search of the alert indices (never through Alerting), for all detectors, a detector id or a detector type,
 * and sorted on one of {@link GetAlertsRequest#SORTABLE_FIELDS} with tie-breakers.
 * <p>
 * The filters are those of {@link GetAlertsRequest}; the multi value filters are separate fields here.
 */
public class GetAlertsPageRequest extends ActionRequest {

    /** Maximum page size in cursor paging */
    public static final int MAX_SIZE = 1000;

    /** The max result window of the alert indices: pages at an offset must end within it */
    public static final int MAX_RESULT_WINDOW = 10000;

    public enum Direction {
        /** the page after the alert of the cursor */
        NEXT,
        /** the page before the alert of the cursor */
        PREV;

        public static Direction parse(String value) {
            for (Direction direction : values()) {
                if (direction.name().equalsIgnoreCase(value)) {
                    return direction;
                }
            }
            throw new IllegalArgumentException(String.format(Locale.ROOT,
                    "direction [%s] is not supported, supported values are [next, prev]", value));
        }

        public String value() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    private final String detectorId;
    private final String logType;
    private final Table table;
    private final String severityLevel;
    private final String alertState;
    private final List<String> severityLevels;
    private final List<String> alertStates;
    private final Instant startTime;
    private final Instant endTime;
    private final String searchAfter;
    private final Direction direction;

    /**
     * @param severityLevel a single severity level or ALL
     * @param alertState a single alert state or ALL
     * @param severityLevels severity levels to filter on (empty for no filter, severityLevel must then be ALL)
     * @param alertStates alert states to filter on (empty for no filter, alertState must then be ALL)
     * @param searchAfter the cursor of the alert the page is after or before, null for a page at an offset
     */
    public GetAlertsPageRequest(
            String detectorId,
            String logType,
            Table table,
            String severityLevel,
            String alertState,
            List<String> severityLevels,
            List<String> alertStates,
            Instant startTime,
            Instant endTime,
            String searchAfter,
            Direction direction
    ) {
        super();
        this.detectorId = detectorId;
        this.logType = logType;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.severityLevels = severityLevels != null ? List.copyOf(severityLevels) : List.of();
        this.alertStates = alertStates != null ? List.copyOf(alertStates) : List.of();
        this.startTime = startTime;
        this.endTime = endTime;
        this.searchAfter = searchAfter;
        this.direction = direction != null ? direction : Direction.NEXT;
    }

    public GetAlertsPageRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant(),
                sin.readOptionalString(),
                sin.readEnum(Direction.class)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(detectorId);
        out.writeOptionalString(logType);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
        out.writeStringCollection(severityLevels);
        out.writeStringCollection(alertStates);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
        out.writeOptionalString(searchAfter);
        out.writeEnum(direction);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (table == null) {
            return addValidationError("table must be set", null);
        }
        // the sort and search string are validated as for the alerts of all detectors in offset paging, for every request
        ActionRequestValidationException tableValidation = new GetAlertsRequest(null, null, table, GetAlertsRequest.ALL,
                GetAlertsRequest.ALL, startTime, endTime).validate();
        if (tableValidation != null) {
            for (String error : tableValidation.validationErrors()) {
                if (error.startsWith("size must") == false) {
                    validationException = addValidationError(error, validationException);
                }
            }
        }
        if (severityLevels.isEmpty() == false) {
            validationException = GetAlertsRequest.validateSeverityLevels(severityLevels, validationException);
        }
        if (alertStates.isEmpty() == false) {
            validationException = GetAlertsRequest.validateAlertStates(alertStates, validationException);
        }
        if (severityLevels.isEmpty() == false && GetAlertsRequest.ALL.equals(severityLevel) == false) {
            validationException = addValidationError("only one of severityLevel and severityLevels can be specified", validationException);
        }
        if (alertStates.isEmpty() == false && GetAlertsRequest.ALL.equals(alertState) == false) {
            validationException = addValidationError("only one of alertState and alertStates can be specified", validationException);
        }
        if (searchAfter == null) {
            if (table.getSize() < 0 || table.getSize() > MAX_SIZE) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "size must be between 0 and %d", MAX_SIZE), validationException);
            }
            if (direction != Direction.NEXT) {
                validationException = addValidationError("direction [prev] requires searchAfter", validationException);
            }
            if (table.getStartIndex() >= 0 && (long) table.getStartIndex() + table.getSize() > MAX_RESULT_WINDOW) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "Result window is too large, startIndex + size must be less than or equal to [%d] but was [%d]. " +
                                "Use searchAfter with the next_cursor of a page to get alerts beyond it",
                        MAX_RESULT_WINDOW, (long) table.getStartIndex() + table.getSize()), validationException);
            }
        } else {
            if (table.getSize() < 1 || table.getSize() > MAX_SIZE) {
                validationException = addValidationError(String.format(Locale.ROOT,
                        "size must be between 1 and %d with searchAfter", MAX_SIZE), validationException);
            }
            if (table.getStartIndex() != 0) {
                validationException = addValidationError("startIndex cannot be used with searchAfter", validationException);
            }
            try {
                AlertsCursor.decode(searchAfter, table);
            } catch (IllegalArgumentException e) {
                validationException = addValidationError(e.getMessage(), validationException);
            }
        }
        return validationException;
    }

    /** The decoded cursor, null for a page at an offset. Only call it on a valid request. */
    public AlertsCursor getCursor() {
        return searchAfter != null ? AlertsCursor.decode(searchAfter, table) : null;
    }

    public String getDetectorId() {
        return detectorId;
    }

    public String getLogType() {
        return logType;
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

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public String getSearchAfter() {
        return searchAfter;
    }

    public Direction getDirection() {
        return direction;
    }
}
