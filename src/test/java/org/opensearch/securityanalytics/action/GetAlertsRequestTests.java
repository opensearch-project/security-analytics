/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.opensearch.Version;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

public class GetAlertsRequestTests extends OpenSearchTestCase {

    public void testValidate_noDetectorIdAndNoLogTypeIsValid() {
        assertNull(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of()).validate());
        assertNull(request("", null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of()).validate());
        assertNull(request("detector_id", null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of()).validate());
        assertNull(request(null, "windows", table("start_time", "asc"), "ALL", "ALL", List.of(), List.of()).validate());
    }

    public void testValidate_sortString() {
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            assertNull(sortString, request(null, null, table(sortString, "desc"), "ALL", "ALL", List.of(), List.of()).validate());
        }
        for (String sortString : List.of("monitor_name", "trigger_name", "id", "end_time", "START_TIME", "")) {
            assertValidationError(request(null, null, table(sortString, "asc"), "ALL", "ALL", List.of(), List.of()),
                    "sortString [" + sortString + "] is not supported");
        }
    }

    public void testValidate_sortOrder() {
        for (String sortOrder : List.of("asc", "desc", "ASC", "Desc")) {
            assertNull(sortOrder, request(null, null, table("start_time", sortOrder), "ALL", "ALL", List.of(), List.of()).validate());
        }
        for (String sortOrder : List.of("ascending", "foo", "")) {
            assertValidationError(request(null, null, table("start_time", sortOrder), "ALL", "ALL", List.of(), List.of()),
                    "sortOrder [" + sortOrder + "] is not supported");
        }
    }

    public void testValidate_pagination() {
        assertNull(request(null, null, new Table("asc", "start_time", null, 0, 0, ""), "ALL", "ALL", List.of(), List.of()).validate());
        assertValidationError(request(null, null, new Table("asc", "start_time", null, -1, 0, ""), "ALL", "ALL", List.of(), List.of()),
                "size must be greater than or equal to 0");
        assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, -1, ""), "ALL", "ALL", List.of(), List.of()),
                "startIndex must be greater than or equal to 0");
    }

    public void testValidate_searchString() {
        for (String searchString : List.of("", "detector", "my-detector AND trigger*", "*leading", "\"quoted phrase\"", "name:(a OR b)")) {
            assertNull(searchString, request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL",
                    List.of(), List.of()).validate());
        }
        for (String searchString : List.of("(foo", "foo AND", "\"unterminated", "[a TO")) {
            assertValidationError(request(null, null, new Table("asc", "start_time", null, 10, 0, searchString), "ALL", "ALL",
                    List.of(), List.of()), "searchString [" + searchString + "] is not a valid query string");
        }
    }

    public void testValidate_multiValueFilters() {
        assertNull(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of("1", "2"), List.of("ACTIVE", "ACKNOWLEDGED")).validate());
        // the single value filters default to ALL, null is treated the same
        assertNull(request(null, null, table("start_time", "asc"), null, null, List.of("1"), List.of("COMPLETED")).validate());

        assertValidationError(request(null, null, table("start_time", "asc"), "1", "ALL", List.of("1", "2"), List.of()),
                "only one of severityLevel and severityLevels can be specified");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ACTIVE", List.of(), List.of("ACTIVE")),
                "only one of alertState and alertStates can be specified");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of("ALL"), List.of()),
                "must not contain blank values or [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of("ACTIVE", "FOO")),
                "contains invalid values [FOO]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of("ALL")),
                "contains invalid values [ALL]");
        assertValidationError(request(null, null, table("start_time", "asc"), "ALL", "ALL", List.of(), List.of("active")),
                "contains invalid values [active]");
    }

    public void testValidate_reportsAllErrors() {
        ActionRequestValidationException e = request(null, null, table("monitor_name", "up"), "1", "ALL", List.of("2"), List.of()).validate();
        assertNotNull(e);
        assertEquals(3, e.validationErrors().size());
    }

    public void testStreamRoundTrip() throws IOException {
        GetAlertsRequest request = new GetAlertsRequest(
                "detector_id",
                "windows",
                new Table("desc", "severity", "_first", 7, 3, "my search"),
                "ALL",
                "ALL",
                List.of("1", "2"),
                List.of("ACTIVE", "ACKNOWLEDGED"),
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
        assertEquals("ALL", newRequest.getSeverityLevel());
        assertEquals("ALL", newRequest.getAlertState());
        assertEquals(List.of("1", "2"), newRequest.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), newRequest.getAlertStates());
        assertEquals(Instant.ofEpochMilli(1000L), newRequest.getStartTime());
        assertEquals(Instant.ofEpochMilli(2000L), newRequest.getEndTime());
    }

    public void testStreamRoundTrip_olderVersionDropsMultiValueFilters() throws IOException {
        GetAlertsRequest request = new GetAlertsRequest(
                null,
                null,
                new Table("asc", "start_time", null, 20, 0, ""),
                "3",
                "ACTIVE",
                List.of("1", "2"),
                List.of("COMPLETED"),
                null,
                null
        );
        BytesStreamOutput out = new BytesStreamOutput();
        out.setVersion(Version.V_3_9_0);
        request.writeTo(out);
        StreamInput sin = out.bytes().streamInput();
        sin.setVersion(Version.V_3_9_0);
        GetAlertsRequest newRequest = new GetAlertsRequest(sin);

        assertNull(newRequest.getDetectorId());
        assertNull(newRequest.getLogType());
        assertEquals(request.getTable(), newRequest.getTable());
        assertEquals("3", newRequest.getSeverityLevel());
        assertEquals("ACTIVE", newRequest.getAlertState());
        assertEquals(List.of(), newRequest.getSeverityLevels());
        assertEquals(List.of(), newRequest.getAlertStates());
        assertNull(newRequest.getStartTime());
        assertNull(newRequest.getEndTime());
        // everything written was consumed
        assertEquals(-1, sin.read());
    }

    public void testStreamRead_fromOlderVersionWithoutMultiValueFilters() throws IOException {
        // what a 3.9 node writes: the request without the multi value filters
        BytesStreamOutput out = new BytesStreamOutput();
        out.setVersion(Version.V_3_9_0);
        out.writeOptionalString("detector_id");
        out.writeOptionalString(null);
        new Table("asc", "start_time", null, 20, 0, "").writeTo(out);
        out.writeString("ALL");
        out.writeString("ALL");
        out.writeOptionalInstant(null);
        out.writeOptionalInstant(null);
        StreamInput sin = out.bytes().streamInput();
        sin.setVersion(Version.V_3_9_0);
        GetAlertsRequest request = new GetAlertsRequest(sin);
        assertEquals("detector_id", request.getDetectorId());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
        assertNull(request.validate());
    }

    public void testLegacyConstructorDefaultsMultiValueFilters() {
        GetAlertsRequest request = new GetAlertsRequest("d", null, table("start_time", "asc"), "ALL", "ALL", null, null);
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
    }

    private static Table table(String sortString, String sortOrder) {
        return new Table(sortOrder, sortString, null, 20, 0, "");
    }

    private static GetAlertsRequest request(String detectorId, String logType, Table table, String severityLevel, String alertState,
                                            List<String> severityLevels, List<String> alertStates) {
        return new GetAlertsRequest(detectorId, logType, table, severityLevel, alertState, severityLevels, alertStates, null, null);
    }

    private static void assertValidationError(GetAlertsRequest request, String expectedMessage) {
        ActionRequestValidationException e = request.validate();
        assertNotNull("expected a validation error containing: " + expectedMessage, e);
        assertTrue(e.getMessage(), e.getMessage().contains(expectedMessage));
    }
}
