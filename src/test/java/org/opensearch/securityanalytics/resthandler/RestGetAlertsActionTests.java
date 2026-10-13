/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsPageAction;
import org.opensearch.securityanalytics.action.GetAlertsPageRequest;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.alerts.AlertsCursor;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestChannel;
import org.opensearch.test.rest.FakeRestRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class RestGetAlertsActionTests extends OpenSearchTestCase {

    public void testDefaults() throws Exception {
        GetAlertsRequest request = parse(Map.of());
        assertNull(request.getDetectorId());
        assertNull(request.getLogType());
        assertEquals(new Table("asc", "start_time", null, 20, 0, ""), request.getTable());
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
        assertNull(request.getStartTime());
        assertNull(request.getEndTime());
        assertNull(request.validate());
    }

    public void testMultiValueFilters() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("severityLevels", " 1, 2,,");
        params.put("alertStates", "active,Acknowledged");
        GetAlertsRequest request = parse(params);
        // sent as comma separated lists in the single value fields
        assertEquals("1,2", request.getSeverityLevel());
        assertEquals("ACTIVE,ACKNOWLEDGED", request.getAlertState());
        assertEquals(List.of("1", "2"), request.getSeverityLevels());
        assertEquals(List.of("ACTIVE", "ACKNOWLEDGED"), request.getAlertStates());
        assertNull(request.validate());

        // a single value is sent as the single value filter
        params.put("severityLevels", " 3 ");
        params.put("alertStates", "completed");
        request = parse(params);
        assertEquals("3", request.getSeverityLevel());
        assertEquals("COMPLETED", request.getAlertState());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
        assertNull(request.validate());

        // the multi value filters can be combined with the single value filters at ALL
        params.put("severityLevel", "ALL");
        params.put("alertState", "ALL");
        request = parse(params);
        assertEquals("3", request.getSeverityLevel());
        assertEquals("COMPLETED", request.getAlertState());

        params.clear();
        params.put("severityLevels", ",");
        params.put("alertStates", "");
        request = parse(params);
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());

        params.clear();
        params.put("severityLevel", "2");
        params.put("alertState", "AUDIT");
        request = parse(params);
        assertEquals("2", request.getSeverityLevel());
        assertEquals("AUDIT", request.getAlertState());
        assertNull(request.validate());
    }

    public void testMultiValueFilters_validation() {
        assertBadRequest(Map.of("severityLevel", "1", "severityLevels", "1,2"), "only one of severityLevel and severityLevels can be specified");
        assertBadRequest(Map.of("severityLevel", "1", "severityLevels", "1"), "only one of severityLevel and severityLevels can be specified");
        assertBadRequest(Map.of("alertState", "ACTIVE", "alertStates", "ACTIVE"), "only one of alertState and alertStates can be specified");
        assertBadRequest(Map.of("alertState", "AUDIT", "alertStates", "ACTIVE,ACKNOWLEDGED"),
                "only one of alertState and alertStates can be specified");
        assertBadRequest(Map.of("severityLevels", "ALL"), "severityLevels [ALL] must not contain blank values or [ALL]");
        assertBadRequest(Map.of("severityLevels", "1,ALL"), "severityLevels [1, ALL] must not contain blank values or [ALL]");
        assertBadRequest(Map.of("alertStates", "ALL"), "alertStates [ALL] contains invalid values [ALL]");
        assertBadRequest(Map.of("alertStates", "AUDIT"), "alertStates [AUDIT] contains invalid values [AUDIT]");
        assertBadRequest(Map.of("alertStates", "audit"), "alertStates [AUDIT] contains invalid values [AUDIT]");
        assertBadRequest(Map.of("alertStates", "ACTIVE,AUDIT"), "contains invalid values [AUDIT]");
        assertBadRequest(Map.of("alertStates", "ACTIVE,FOO"), "alertStates [ACTIVE, FOO] contains invalid values [FOO]");
    }

    public void testMultiValueFilters_validationReportsAllErrorsOnce() {
        ActionRequestValidationException e = expectThrows(ActionRequestValidationException.class, () -> parse(Map.of(
                "severityLevel", "1", "severityLevels", "1,ALL", "alertStates", "ACTIVE,FOO", "sortString", "monitor_name")));
        assertEquals(e.validationErrors().toString(), List.of(
                "only one of severityLevel and severityLevels can be specified",
                "severityLevels [1, ALL] must not contain blank values or [ALL]",
                "alertStates [ACTIVE, FOO] contains invalid values [FOO], supported values are [ACTIVE, ACKNOWLEDGED, COMPLETED, ERROR, DELETED]",
                "sortString [monitor_name] is not supported, supported values are " + GetAlertsRequest.SORTABLE_FIELDS
        ), e.validationErrors());
        assertEquals(RestStatus.BAD_REQUEST, ExceptionsHelper.status(e));
    }

    private void assertBadRequest(Map<String, String> params, String expectedMessage) {
        ActionRequestValidationException e = expectThrows(ActionRequestValidationException.class, () -> parse(params));
        assertTrue(params + " -> " + e.getMessage(), e.getMessage().contains(expectedMessage));
        assertEquals(RestStatus.BAD_REQUEST, ExceptionsHelper.status(e));
    }

    public void testTableParams() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", "d1");
        params.put("sortString", "monitor_name.keyword");
        params.put("sortOrder", "desc");
        params.put("size", "0");
        params.put("startIndex", "40");
        params.put("searchString", "my detector");
        params.put("startTime", "1000");
        params.put("endTime", "2000");
        GetAlertsRequest request = parse(params);
        assertEquals("d1", request.getDetectorId());
        assertEquals(new Table("desc", "monitor_name.keyword", null, 0, 40, "my detector"), request.getTable());
        assertEquals(1000L, request.getStartTime().toEpochMilli());
        assertEquals(2000L, request.getEndTime().toEpochMilli());
        assertNull(request.validate());
    }

    public void testCursorPaging_defaults() throws Exception {
        GetAlertsPageRequest request = parseCursorPaging(Map.of("paging", "cursor"));
        assertNull(request.getDetectorId());
        assertNull(request.getLogType());
        assertEquals(new Table("asc", "start_time", null, 20, 0, ""), request.getTable());
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        assertEquals(List.of(), request.getSeverityLevels());
        assertEquals(List.of(), request.getAlertStates());
        assertNull(request.getSearchAfter());
        assertEquals(GetAlertsPageRequest.Direction.NEXT, request.getDirection());
        assertNull(request.validate());
    }

    public void testCursorPaging_params() throws Exception {
        Table table = new Table("desc", "severity", null, 50, 0, "windetector");
        String cursor = AlertsCursor.encode(table, new Object[] { "1", 5L, "index", "m1", 3L });
        Map<String, String> params = new HashMap<>();
        params.put("paging", "cursor");
        params.put("detector_id", "d1");
        params.put("sortString", "severity");
        params.put("sortOrder", "desc");
        params.put("size", "50");
        params.put("searchString", "windetector");
        params.put("severityLevels", "1,2");
        params.put("alertStates", "active");
        params.put("startTime", "1000");
        params.put("endTime", "2000");
        params.put("searchAfter", cursor);
        params.put("direction", "PREV");
        GetAlertsPageRequest request = parseCursorPaging(params);
        assertEquals("d1", request.getDetectorId());
        assertEquals(table, request.getTable());
        assertEquals("ALL", request.getSeverityLevel());
        assertEquals("ALL", request.getAlertState());
        // multi value filters with a single value stay multi value filters
        assertEquals(List.of("1", "2"), request.getSeverityLevels());
        assertEquals(List.of("ACTIVE"), request.getAlertStates());
        assertEquals(1000L, request.getStartTime().toEpochMilli());
        assertEquals(2000L, request.getEndTime().toEpochMilli());
        assertEquals(cursor, request.getSearchAfter());
        assertEquals(GetAlertsPageRequest.Direction.PREV, request.getDirection());

        // an offset page in cursor paging
        request = parseCursorPaging(Map.of("paging", "cursor", "detectorType", "windows", "startIndex", "40", "size", "0"));
        assertEquals("windows", request.getLogType());
        assertEquals(new Table("asc", "start_time", null, 0, 40, ""), request.getTable());
        assertNull(request.getSearchAfter());
    }

    public void testCursorPaging_validation() {
        Table table = new Table("asc", "start_time", null, 20, 0, "");
        String cursor = AlertsCursor.encode(table, new Object[] { 5L, "index", "m1", 3L });
        assertBadRequest(Map.of("paging", "offset"), "paging [offset] is not supported, supported values are [cursor]");
        assertBadRequest(Map.of("paging", ""), "paging [] is not supported, supported values are [cursor]");
        assertBadRequest(Map.of("paging", "cursor", "direction", "back"), "direction [back] is not supported");
        assertBadRequest(Map.of("paging", "cursor", "direction", "prev"), "direction [prev] requires searchAfter");
        assertBadRequest(Map.of("paging", "cursor", "searchAfter", cursor, "startIndex", "0"), "startIndex cannot be used with searchAfter");
        assertBadRequest(Map.of("paging", "cursor", "searchAfter", cursor, "startIndex", "20"), "startIndex cannot be used with searchAfter");
        assertBadRequest(Map.of("paging", "cursor", "searchAfter", "tampered"), "searchAfter is not a valid cursor");
        assertBadRequest(Map.of("paging", "cursor", "searchAfter", cursor, "sortOrder", "desc"), "not of the requested sort");
        assertBadRequest(Map.of("paging", "cursor", "size", "1001"), "size must be between 0 and 1000");
        assertBadRequest(Map.of("paging", "cursor", "startIndex", "9990", "size", "20"), "Result window is too large");
        assertBadRequest(Map.of("paging", "cursor", "detector_id", "d1", "sortString", "trigger_name"),
                "sortString [trigger_name] is not supported");
        assertBadRequest(Map.of("paging", "cursor", "severityLevel", "1", "severityLevels", "1"),
                "only one of severityLevel and severityLevels can be specified");
        assertBadRequest(Map.of("paging", "cursor", "alertStates", "audit"), "alertStates [AUDIT] contains invalid values [AUDIT]");

        ActionRequestValidationException e = expectThrows(ActionRequestValidationException.class, () -> parseCursorPaging(Map.of(
                "paging", "cursor", "direction", "prev", "size", "5000")));
        assertEquals(e.validationErrors().toString(), List.of("size must be between 0 and 1000", "direction [prev] requires searchAfter"),
                e.validationErrors());
    }

    /** The cursor paging params are only recognized with paging: requests without it are rejected as before. */
    public void testCursorPagingParamsWithoutPaging_unrecognized() {
        for (String param : List.of("searchAfter", "direction")) {
            IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> parse(Map.of(param, "next")));
            assertTrue(e.getMessage(), e.getMessage().contains("unrecognized parameter: [" + param + "]"));
        }
    }

    private GetAlertsPageRequest parseCursorPaging(Map<String, String> params) throws Exception {
        NodeClient client = mock(NodeClient.class);
        AtomicReference<GetAlertsPageRequest> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(1));
            return null;
        }).when(client).execute(eq(GetAlertsPageAction.INSTANCE), any(GetAlertsPageRequest.class), any(ActionListener.class));

        FakeRestRequest restRequest = new FakeRestRequest.Builder(xContentRegistry()).withParams(new HashMap<>(params)).build();
        new RestGetAlertsAction().handleRequest(restRequest, new FakeRestChannel(restRequest, true, 1), client);
        assertNotNull("GetAlertsPageAction was not executed", captured.get());
        verify(client, never()).execute(eq(GetAlertsAction.INSTANCE), any(), any());
        return captured.get();
    }

    private GetAlertsRequest parse(Map<String, String> params) throws Exception {
        NodeClient client = mock(NodeClient.class);
        AtomicReference<GetAlertsRequest> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(1));
            return null;
        }).when(client).execute(eq(GetAlertsAction.INSTANCE), any(GetAlertsRequest.class), any(ActionListener.class));

        FakeRestRequest restRequest = new FakeRestRequest.Builder(xContentRegistry()).withParams(new HashMap<>(params)).build();
        new RestGetAlertsAction().handleRequest(restRequest, new FakeRestChannel(restRequest, true, 1), client);
        assertNotNull("GetAlertsAction was not executed", captured.get());
        verify(client, never()).execute(eq(GetAlertsPageAction.INSTANCE), any(), any());
        return captured.get();
    }
}
