/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.alerts.AlertsCursor;
import org.opensearch.test.OpenSearchTestCase;

import static org.opensearch.securityanalytics.action.GetAlertsPageRequest.Direction.NEXT;
import static org.opensearch.securityanalytics.action.GetAlertsPageRequest.Direction.PREV;

public class GetAlertsPageRequestTests extends OpenSearchTestCase {

    private static final String ALL = GetAlertsRequest.ALL;

    private static final Table TABLE = new Table("desc", "start_time", null, 20, 0, "windetector");
    private static final String CURSOR = AlertsCursor.encode(TABLE, new Object[] { 5L, "index", "m1", 3L });

    private static GetAlertsPageRequest request(String detectorId, String logType, Table table, String searchAfter,
                                                GetAlertsPageRequest.Direction direction) {
        return new GetAlertsPageRequest(detectorId, logType, table, ALL, ALL, List.of(), List.of(), null, null, searchAfter, direction);
    }

    public void testStreams() throws IOException {
        GetAlertsPageRequest request = new GetAlertsPageRequest("d1", "windows", TABLE, ALL, "AUDIT", List.of("1", "2"),
                List.of(), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000), CURSOR, PREV);
        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);
        GetAlertsPageRequest read = new GetAlertsPageRequest(out.bytes().streamInput());
        assertEquals("d1", read.getDetectorId());
        assertEquals("windows", read.getLogType());
        assertEquals(TABLE, read.getTable());
        assertEquals(ALL, read.getSeverityLevel());
        assertEquals("AUDIT", read.getAlertState());
        assertEquals(List.of("1", "2"), read.getSeverityLevels());
        assertEquals(List.of(), read.getAlertStates());
        assertEquals(1000L, read.getStartTime().toEpochMilli());
        assertEquals(2000L, read.getEndTime().toEpochMilli());
        assertEquals(CURSOR, read.getSearchAfter());
        assertEquals(PREV, read.getDirection());

        GetAlertsPageRequest minimal = request(null, null, TABLE, null, null);
        out = new BytesStreamOutput();
        minimal.writeTo(out);
        read = new GetAlertsPageRequest(out.bytes().streamInput());
        assertNull(read.getDetectorId());
        assertNull(read.getLogType());
        assertNull(read.getSearchAfter());
        assertNull(read.getStartTime());
        assertEquals(NEXT, read.getDirection());
    }

    public void testValidate_valid() {
        assertNull(request(null, null, TABLE, null, NEXT).validate());
        assertNull(request(null, null, TABLE, CURSOR, NEXT).validate());
        assertNull(request(null, null, TABLE, CURSOR, PREV).validate());
        assertNull(request("d1", null, TABLE, CURSOR, NEXT).validate());
        assertNull(request(null, "windows", TABLE, CURSOR, NEXT).validate());
        // the last page within the max result window, and size 0 (the total only) without cursor
        assertNull(request(null, null, new Table("asc", "severity", null, 1000, 9000, null), null, NEXT).validate());
        assertNull(request(null, null, new Table("asc", "severity", null, 0, 0, null), null, NEXT).validate());
        assertNull(new GetAlertsPageRequest(null, null, TABLE, ALL, ALL, List.of("1"), List.of("ACTIVE"), null, null, CURSOR, NEXT)
                .validate());
        // single value filters as in offset paging, AUDIT included
        assertNull(new GetAlertsPageRequest("d1", null, TABLE, "1", "AUDIT", List.of(), List.of(), null, null, CURSOR, NEXT).validate());
        assertEquals(CURSOR, AlertsCursor.encode(TABLE, request(null, null, TABLE, CURSOR, NEXT).getCursor().getSortValues()));
        assertNull(request(null, null, TABLE, null, NEXT).getCursor());
    }

    public void testValidate_sortOnSortableFieldsOnly() {
        // also for a detector id or type: the alerts are always searched directly, with tie-breakers
        for (String detectorId : new String[] { null, "d1" }) {
            assertInvalid(request(detectorId, null, new Table("asc", "trigger_name", null, 20, 0, null), null, NEXT),
                    "sortString [trigger_name] is not supported, supported values are " + GetAlertsRequest.SORTABLE_FIELDS);
        }
        assertInvalid(request(null, "windows", new Table("asc", "monitor_name", null, 20, 0, null), null, NEXT),
                "sortString [monitor_name] is not supported");
        assertInvalid(request(null, null, new Table("up", "start_time", null, 20, 0, null), null, NEXT),
                "sortOrder [up] is not supported");
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 20, 0, "a:("), null, NEXT),
                "searchString [a:(] is not a valid query string");
    }

    public void testValidate_size() {
        assertInvalid(request(null, null, new Table("asc", "start_time", null, -1, 0, null), null, NEXT), "size must be between 0 and 1000");
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 1001, 0, null), null, NEXT), "size must be between 0 and 1000");
        Table zero = new Table("desc", "start_time", null, 0, 0, null);
        assertInvalid(request(null, null, zero, AlertsCursor.encode(zero, new Object[] { 5L, "i", "m", 1L }), NEXT),
                "size must be between 1 and 1000 with searchAfter");
        Table tooLarge = new Table("desc", "start_time", null, 1001, 0, null);
        assertInvalid(request(null, null, tooLarge, AlertsCursor.encode(tooLarge, new Object[] { 5L, "i", "m", 1L }), NEXT),
                "size must be between 1 and 1000 with searchAfter");
        ActionRequestValidationException e = request(null, null, new Table("asc", "start_time", null, -1, 0, null), null, NEXT).validate();
        // the size error of offset paging is not reported in addition
        assertEquals(e.validationErrors().toString(), 1, e.validationErrors().size());
    }

    public void testValidate_offset() {
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 20, -1, null), null, NEXT),
                "startIndex must be greater than or equal to 0");
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 20, 9981, null), null, NEXT),
                "Result window is too large, startIndex + size must be less than or equal to [10000] but was [10001]");
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 1000, Integer.MAX_VALUE, null), null, NEXT),
                "Result window is too large");
        assertInvalid(request(null, null, TABLE, null, PREV), "direction [prev] requires searchAfter");
        Table withStartIndex = new Table("desc", "start_time", null, 20, 20, "windetector");
        assertInvalid(request(null, null, withStartIndex, CURSOR, NEXT), "startIndex cannot be used with searchAfter");
    }

    public void testValidate_cursor() {
        assertInvalid(request(null, null, TABLE, "garbage!", NEXT), "searchAfter is not a valid cursor");
        assertInvalid(request(null, null, TABLE, "", NEXT), "searchAfter must not be empty");
        assertInvalid(request(null, null, new Table("asc", "start_time", null, 20, 0, null), CURSOR, NEXT),
                "not of the requested sort");
        assertInvalid(request(null, null, new Table("desc", "severity", null, 20, 0, null), CURSOR, NEXT),
                "not of the requested sort");
        assertInvalid(request(null, null, TABLE, AlertsCursor.encode(TABLE, new Object[] { 5L, "index", 3L }), NEXT),
                "searchAfter has 3 sort values, expected 4");
        // the cursor's search string, filters and page size do not matter: they are not part of the cursor
        assertNull(request(null, null, new Table("desc", "start_time", null, 5, 0, "other"), CURSOR, PREV).validate());
    }

    public void testValidate_filters() {
        assertInvalid(new GetAlertsPageRequest(null, null, TABLE, "1", ALL, List.of("1", "2"), List.of(), null, null, null, NEXT),
                "only one of severityLevel and severityLevels can be specified");
        assertInvalid(new GetAlertsPageRequest(null, null, TABLE, ALL, "ACTIVE", List.of(), List.of("ACTIVE"), null, null, null, NEXT),
                "only one of alertState and alertStates can be specified");
        assertInvalid(new GetAlertsPageRequest(null, null, TABLE, ALL, ALL, List.of(ALL), List.of(), null, null, null, NEXT),
                "severityLevels [ALL] must not contain blank values or [ALL]");
        assertInvalid(new GetAlertsPageRequest(null, null, TABLE, ALL, ALL, List.of(), List.of(Alert.State.AUDIT.name()), null, null,
                null, NEXT), "alertStates [AUDIT] contains invalid values [AUDIT]");
    }

    public void testDirection() {
        assertEquals(NEXT, GetAlertsPageRequest.Direction.parse("next"));
        assertEquals(PREV, GetAlertsPageRequest.Direction.parse("PREV"));
        assertEquals("prev", PREV.value());
        IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> GetAlertsPageRequest.Direction.parse("back"));
        assertEquals("direction [back] is not supported, supported values are [next, prev]", e.getMessage());
    }

    public void testResponse() throws IOException {
        GetAlertsPageResponse response = new GetAlertsPageResponse(List.of(), 37512L, "next", null);
        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);
        StreamInput in = out.bytes().streamInput();
        GetAlertsPageResponse read = new GetAlertsPageResponse(in);
        assertEquals(List.of(), read.getAlerts());
        assertEquals(37512L, read.getTotalAlerts());
        assertEquals("next", read.getNextCursor());
        assertNull(read.getPrevCursor());

        Map<String, Object> json = XContentHelper.convertToMap(BytesReference.bytes(response.toXContent(JsonXContent.contentBuilder(),
                ToXContent.EMPTY_PARAMS)), false, org.opensearch.common.xcontent.XContentType.JSON).v2();
        assertEquals(List.of(), json.get("alerts"));
        assertEquals(37512, json.get("total_alerts"));
        assertEquals("next", json.get("next_cursor"));
        // the cursors are always in the response, null when there is no page
        assertTrue(json.containsKey("prev_cursor"));
        assertNull(json.get("prev_cursor"));
        assertEquals(4, json.size());
    }

    private static void assertInvalid(GetAlertsPageRequest request, String expectedMessage) {
        ActionRequestValidationException e = request.validate();
        assertNotNull(expectedMessage, e);
        assertTrue(e.getMessage(), e.getMessage().contains(expectedMessage));
    }
}
