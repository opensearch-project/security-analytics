/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

public class GetAlertsRequestTests extends OpenSearchTestCase {

    public void testValidate_noDetectorIdAndNoLogTypeIsValid() {
        assertNull(request(null, null, table("start_time", "asc"), "ALL", "ALL").validate());
        assertNull(request("", null, table("start_time", "asc"), "ALL", "ALL").validate());
        assertNull(request("detector_id", null, table("start_time", "asc"), "ALL", "ALL").validate());
        assertNull(request(null, "windows", table("start_time", "asc"), "ALL", "ALL").validate());
    }

    public void testValidate_sortString_allDetectors() {
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            assertNull(sortString, request(null, null, table(sortString, "desc"), "ALL", "ALL").validate());
            assertNull(sortString, request("", null, table(sortString, "asc"), "ALL", "ALL").validate());
        }
        // other alert fields, including fields that could be sorted on before (dates, keywords, keyword sub-fields,
        // numerics), text fields, nested/object fields, id and version
        for (String sortString : List.of("end_time", "last_notification_time", "acknowledged_time", "trigger_name.keyword",
                "workflow_id", "workflow_name", "monitor_id", "trigger_id", "execution_id", "finding_ids.keyword",
                "related_doc_ids.keyword", "associated_alert_ids.keyword", "clusters.keyword", "schema_version", "monitor_version",
                "monitor_name", "trigger_name", "error_message", "finding_ids", "id", "version",
                "alert_history.timestamp", "action_execution_results.last_execution_time", "monitor_user.name.keyword",
                "agg_alert_content.bucket_key", "START_TIME", "foo", "")) {
            assertValidationError(request(null, null, table(sortString, "asc"), "ALL", "ALL"),
                    "sortString [" + sortString + "] is not supported, supported values are [start_time, monitor_name.keyword, state, severity]");
            assertValidationError(request("", null, table(sortString, "asc"), "ALL", "ALL"),
                    "sortString [" + sortString + "] is not supported");
        }
    }

    public void testSortableFields() {
        assertEquals(List.of("start_time", "monitor_name.keyword", "state", "severity"), GetAlertsRequest.SORTABLE_FIELDS);
        assertEquals("start_time", GetAlertsRequest.DEFAULT_SORT_STRING);
        assertTrue(GetAlertsRequest.SORTABLE_FIELDS.contains(GetAlertsRequest.DEFAULT_SORT_STRING));
    }

    /** Requests for a detector id or a detector type pass any sort field on to Alerting, as before. */
    public void testValidate_sortString_notValidatedForDetectorIdAndDetectorType() {
        for (String sortString : List.of("end_time", "last_notification_time", "acknowledged_time", "trigger_name.keyword",
                "workflow_id", "monitor_id", "version", "id", "monitor_name", "foo", "START_TIME", "start_time")) {
            assertNull(sortString, request("detector_id", null, table(sortString, "asc"), "ALL", "ALL").validate());
            assertNull(sortString, request(null, "windows", table(sortString, "desc"), "ALL", "ALL").validate());
            assertNull(sortString, request("detector_id", "windows", table(sortString, "desc"), "ALL", "ALL").validate());
        }
    }

    public void testValidate_sortOrder() {
        for (String sortOrder : List.of("asc", "desc", "ASC", "Desc")) {
            assertNull(sortOrder, request(null, null, table("start_time", sortOrder), "ALL", "ALL").validate());
        }
        for (String sortOrder : List.of("ascending", "foo", "")) {
            assertValidationError(request(null, null, table("start_time", sortOrder), "ALL", "ALL"),
                    "sortOrder [" + sortOrder + "] is not supported");
        }
    }

    public void testValidate_pagination() {
        assertNull(request(null, null, new Table("asc", "start_time", null, 0, 0, ""), "ALL", "ALL").validate());
        assertValidationError(request(null, null, new Table("asc", "start_time", null, -1, 0, ""), "ALL", "ALL"),
                "size must be greater than or equal to 0");
        assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, -1, ""), "ALL", "ALL"),
                "startIndex must be greater than or equal to 0");
    }

    public void testValidate_searchString() {
        for (String searchString : List.of("", "detector", "my-detector AND trigger*", "*leading", "\"quoted phrase\"", "name:(a OR b)",
                "trig?er", "monitor_name:value", "trigger_name:\"a phrase\"", "foo\\:bar", "a\\(b\\)", "\\/not-a-regex",
                "/[a-z]+/", "monitor_name:/win.*/", "fuzzy~2", "[a TO b]", "+must -mustNot")) {
            assertNull(searchString, request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL").validate());
        }
        for (String searchString : List.of("(foo", "foo AND", "\"unterminated", "[a TO")) {
            assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL"), "searchString [" + searchString + "] is not a valid query string");
        }
    }

    /**
     * The validation parser (Lucene's classic QueryParser) has the grammar of OpenSearch's QueryStringQueryParser, which
     * extends it: query_string syntax such as _exists_, ranges and regular expressions is accepted.
     */
    public void testValidate_searchString_queryStringSyntax() {
        for (String searchString : List.of("_exists_:monitor_name", "_exists_:trigger_name AND windows", "NOT _exists_:monitor_name",
                "start_time:[2024-01-01 TO *]", "severity:{1 TO 3}", "trigger_name:/trig.*/", "monitor_name.keyword:windetector")) {
            for (String detectorId : new String[] { null, "detector_id" }) {
                assertNull(searchString, request(detectorId, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL").validate());
            }
        }
    }

    public void testValidate_searchString_invalidRegex() {
        for (String searchString : List.of("/[a-/", "/a(b/", "monitor_name:/[/")) {
            for (String detectorId : new String[] { null, "detector_id" }) {
                assertValidationError(request(detectorId, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL"), "searchString [" + searchString + "] is not a valid query string");
            }
        }
    }

    public void testValidate_searchString_tooComplexRegex() {
        // determinizing this regular expression exceeds Lucene's (and query_string's) default limit of 10000 states
        for (String searchString : List.of("/[ac]*a[ac]{50,200}/", "trigger_name:/(a|b)*a(a|b){30}/")) {
            assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL"), "searchString [" + searchString + "] is not a valid query string");
            assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL"), "Determinizing automaton");
        }
    }

    public void testValidate_multiValueFilters() {
        assertNull(request(null, null, table("start_time", "asc"), "1,2", "ACTIVE,ACKNOWLEDGED").validate());
        assertNull(request("detector_id", null, table("start_time", "asc"), "1,2,3,4", "COMPLETED,ERROR,DELETED").validate());
        // a single value, ALL or null is not a multi value filter
        assertNull(request(null, null, table("start_time", "asc"), "1", "ACTIVE").validate());
        assertNull(request(null, null, table("start_time", "asc"), null, null).validate());

        assertValidationError(request(null, null, table("start_time", "asc"), "1,ALL", "ALL"),
                "severityLevels [1, ALL] must not contain blank values or [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "1,,2", "ALL"),
                "must not contain blank values or [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "1, ", "ALL"),
                "must not contain blank values or [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), ",", "ALL"),
                "must not contain blank values or [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE,FOO"),
                "alertStates [ACTIVE, FOO] contains invalid values [FOO]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE,ALL"),
                "contains invalid values [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE,active"),
                "contains invalid values [active]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE,"),
                "contains invalid values []");
    }

    public void testValidateSeverityLevelsAndAlertStates() {
        assertNull(GetAlertsRequest.validateSeverityLevels(List.of("1"), null));
        assertNull(GetAlertsRequest.validateSeverityLevels(List.of("1", "2"), null));
        assertNull(GetAlertsRequest.validateAlertStates(List.of("ACTIVE"), null));
        assertNull(GetAlertsRequest.validateAlertStates(List.of("ACTIVE", "ACKNOWLEDGED", "COMPLETED", "ERROR", "DELETED"), null));
        assertTrue(GetAlertsRequest.validateSeverityLevels(List.of("ALL"), null).getMessage()
                .contains("severityLevels [ALL] must not contain blank values or [ALL]"));
        assertTrue(GetAlertsRequest.validateAlertStates(List.of("ALL"), null).getMessage()
                .contains("alertStates [ALL] contains invalid values [ALL]"));
        assertTrue(GetAlertsRequest.validateAlertStates(List.of("AUDIT"), null).getMessage()
                .contains("alertStates [AUDIT] contains invalid values [AUDIT]"));
        // errors are added to the given exception
        ActionRequestValidationException e = GetAlertsRequest.validateSeverityLevels(List.of("ALL"), null);
        assertSame(e, GetAlertsRequest.validateAlertStates(List.of("FOO"), e));
        assertEquals(2, e.validationErrors().size());
    }

    public void testValidate_alertStates_audit() {
        // multiple alert states are combined with Alerting's state=ALL filter, which excludes AUDIT alerts, so AUDIT
        // never matches
        for (String detectorId : new String[] { null, "detector_id" }) {
            ActionRequestValidationException e = request(detectorId, null, table("start_time", "asc"), "ALL", "ACTIVE,AUDIT").validate();
            assertNotNull(e);
            assertTrue(e.getMessage(), e.getMessage().contains("contains invalid values [AUDIT]"));
            assertTrue(e.getMessage(), e.getMessage().contains("supported values are [ACTIVE, ACKNOWLEDGED, COMPLETED, ERROR, DELETED]"));
        }
        // the single value alertState keeps passing AUDIT on to Alerting
        assertNull(request(null, null, table("start_time", "asc"), "ALL", "AUDIT").validate());
        assertNull(request("detector_id", null, table("start_time", "asc"), "ALL", "AUDIT").validate());
        // all other states are accepted
        assertNull(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE,ACKNOWLEDGED,COMPLETED,ERROR,DELETED").validate());
    }

    public void testValidate_reportsAllErrors() {
        ActionRequestValidationException e = request(null, null, table("monitor_name", "up"), "1,ALL", "ACTIVE,FOO").validate();
        assertNotNull(e);
        assertEquals(e.validationErrors().toString(), 4, e.validationErrors().size());
    }

    public void testMultiValues() {
        GetAlertsRequest request = request(null, null, table("start_time", "asc"), "1,2", "ACTIVE,ACKNOWLEDGED");
        assertEquals("1,2", request.getSeverityLevel());
        assertEquals("ACTIVE,ACKNOWLEDGED", request.getAlertState());
        assertEquals(List.of("1", "2"), request.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), request.getAlertStates());

        for (String single : new String[] { "ALL", "1", "AUDIT", "", null }) {
            request = request(null, null, table("start_time", "asc"), single, single);
            assertEquals(single, request.getSeverityLevel());
            assertEquals(single, request.getAlertState());
            assertEquals(List.of(), request.getSeverityLevels());
            assertEquals(List.of(), request.getAlertStates());
        }
    }

    public void testStreamRoundTrip() throws IOException {
        GetAlertsRequest request = new GetAlertsRequest(
                "detector_id",
                "windows",
                new Table("desc", "severity", "_first", 7, 3, "my search"),
                "1,2",
                "ACTIVE,ACKNOWLEDGED",
                Instant.ofEpochMilli(1000L),
                Instant.ofEpochMilli(2000L)
        );
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);
        StreamInput sin = out.bytes().streamInput();
        GetAlertsRequest newRequest = new GetAlertsRequest(sin);

        assertEquals("detector_id", newRequest.getDetectorId());
        assertEquals("windows", newRequest.getLogType());
        assertEquals(request.getTable(), newRequest.getTable());
        assertEquals("1,2", newRequest.getSeverityLevel());
        assertEquals("ACTIVE,ACKNOWLEDGED", newRequest.getAlertState());
        assertEquals(List.of("1", "2"), newRequest.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), newRequest.getAlertStates());
        assertEquals(Instant.ofEpochMilli(1000L), newRequest.getStartTime());
        assertEquals(Instant.ofEpochMilli(2000L), newRequest.getEndTime());
        assertEquals(-1, sin.read());
    }

    /**
     * The request is serialized exactly as before the multi value filters were added (they travel in the existing
     * severityLevel and alertState strings), so nodes with and without them can exchange it in both directions.
     */
    public void testStreamFormatUnchanged() throws IOException {
        for (Instant time : new Instant[] { null, Instant.ofEpochMilli(1234L) }) {
            for (String detectorId : new String[] { null, "detector_id" }) {
                Table table = new Table("desc", "severity", "_first", 7, 3, "my search");
                GetAlertsRequest request = new GetAlertsRequest(detectorId, "windows", table, "3", "ACTIVE", time, time);
                BytesStreamOutput out = new BytesStreamOutput();
                request.writeTo(out);

                // the format of GetAlertsRequest without the multi value filters, written field by field
                BytesStreamOutput expected = new BytesStreamOutput();
                expected.writeOptionalString(detectorId);
                expected.writeOptionalString("windows");
                table.writeTo(expected);
                expected.writeString("3");
                expected.writeString("ACTIVE");
                expected.writeOptionalInstant(time);
                expected.writeOptionalInstant(time);
                assertEquals(expected.bytes(), out.bytes());

                // and read back from that format
                StreamInput sin = expected.bytes().streamInput();
                GetAlertsRequest newRequest = new GetAlertsRequest(sin);
                assertEquals(detectorId, newRequest.getDetectorId());
                assertEquals("windows", newRequest.getLogType());
                assertEquals(table, newRequest.getTable());
                assertEquals("3", newRequest.getSeverityLevel());
                assertEquals("ACTIVE", newRequest.getAlertState());
                assertEquals(List.of(), newRequest.getSeverityLevels());
                assertEquals(List.of(), newRequest.getAlertStates());
                assertEquals(time, newRequest.getStartTime());
                assertEquals(time, newRequest.getEndTime());
                assertEquals(-1, sin.read());
            }
        }
    }

    private static Table table(String sortString, String sortOrder) {
        return new Table(sortOrder, sortString, null, 20, 0, "");
    }

    private static GetAlertsRequest request(String detectorId, String logType, Table table, String severityLevel, String alertState) {
        return new GetAlertsRequest(detectorId, logType, table, severityLevel, alertState, null, null);
    }

    private static void assertValidationError(GetAlertsRequest request, String expectedMessage) {
        ActionRequestValidationException e = request.validate();
        assertNotNull("expected a validation error containing: " + expectedMessage, e);
        assertTrue(e.getMessage(), e.getMessage().contains(expectedMessage));
    }
}
