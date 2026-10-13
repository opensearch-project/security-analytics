/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.opensearch.client.Request;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;

/**
 * Cursor paging of the alerts API: GET _plugins/_security_analytics/alerts?paging=cursor[&amp;searchAfter=..][&amp;direction=..].
 */
public class AlertsCursorPagingIT extends AlertsAllDetectorsTestCase {

    /** The alerts API in cursor paging */
    private Map<String, Object> cursorPage(RestClient client, Map<String, String> params) throws IOException {
        Map<String, String> cursorParams = new HashMap<>(params);
        cursorParams.put("paging", "cursor");
        Map<String, Object> body = getAlertsApi(client, cursorParams);
        assertEquals(body.keySet().toString(), Set.of("alerts", "total_alerts", "next_cursor", "prev_cursor"), body.keySet());
        return body;
    }

    private static String nextCursor(Map<String, Object> page) {
        return (String) page.get("next_cursor");
    }

    private static String prevCursor(Map<String, Object> page) {
        return (String) page.get("prev_cursor");
    }

    private static long total(Map<String, Object> page) {
        return ((Number) page.get("total_alerts")).longValue();
    }

    private static Map<String, String> with(Map<String, String> params, String... keyValues) {
        Map<String, String> result = new HashMap<>(params);
        result.putAll(params(keyValues));
        return result;
    }

    /** Walks all pages from the first one with the next cursors, checking the exact total of every page. */
    private List<Map<String, Object>> walkNext(RestClient client, Map<String, String> params, int size, long expectedTotal)
            throws IOException {
        List<Map<String, Object>> pages = new ArrayList<>();
        Map<String, Object> page = cursorPage(client, with(params, "size", String.valueOf(size)));
        assertNull(prevCursor(page));
        while (true) {
            assertEquals(expectedTotal, total(page));
            pages.add(page);
            assertTrue("too many pages", pages.size() <= expectedTotal / size + 2);
            if (nextCursor(page) == null) {
                break;
            }
            assertEquals(size, alertIdsOf(page).size());
            page = cursorPage(client, with(params, "size", String.valueOf(size), "searchAfter", nextCursor(page)));
            assertNotNull(prevCursor(page));
        }
        return pages;
    }

    /** Walks all pages from the last page of the walk back to the first with the prev cursors. */
    private List<Map<String, Object>> walkPrev(RestClient client, Map<String, String> params, int size, Map<String, Object> lastPage)
            throws IOException {
        List<Map<String, Object>> pages = new ArrayList<>();
        pages.add(lastPage);
        Map<String, Object> page = lastPage;
        while (prevCursor(page) != null) {
            page = cursorPage(client, with(params, "size", String.valueOf(size), "searchAfter", prevCursor(page), "direction", "prev"));
            assertNotNull(nextCursor(page));
            pages.add(0, page);
            assertTrue("too many pages", pages.size() <= total(lastPage) / size + 2);
        }
        return pages;
    }

    private static List<String> ids(List<Map<String, Object>> pages) {
        List<String> ids = new ArrayList<>();
        pages.forEach(page -> ids.addAll(alertIdsOf(page)));
        return ids;
    }

    private static List<List<String>> pageIds(List<Map<String, Object>> pages) {
        List<List<String>> ids = new ArrayList<>();
        pages.forEach(page -> ids.add(alertIdsOf(page)));
        return ids;
    }

    private static void assertNoDuplicates(List<String> ids) {
        assertEquals("duplicate alerts", ids.size(), Set.copyOf(ids).size());
    }

    private void assertBadRequest(Map<String, String> params, String expectedMessage) {
        ResponseException e = expectThrows(ResponseException.class, () -> getAlertsApi(client(), params));
        assertEquals(params.toString(), RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        assertTrue(params + " -> " + responseBody(e), responseBody(e).contains(expectedMessage));
    }

    private int status(Map<String, String> params) throws IOException {
        try {
            getAlertsApi(client(), params);
            return RestStatus.OK.getStatus();
        } catch (ResponseException e) {
            return e.getResponse().getStatusLine().getStatusCode();
        }
    }

    /**
     * More than 10,000 alerts (the max result window) of the windows detector, in its active and history alert
     * indices, with pairs of alerts sharing their start time: cursor paging walks all of them in order, without
     * duplicates or gaps, while offset paging stays limited to the first 10,000.
     */
    @SuppressWarnings("unchecked")
    public void testCursorPaging_beyondMaxResultWindow() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        String windowsAlertId = sorted(fixture.windowsAlertIds()).get(0);
        Map<String, Object> template = new HashMap<>(fixture.alertDocs.get(windowsAlertId));
        String activeIndex = (String) template.remove("_index");
        template.remove("_id");
        String historyIndex = historyIndex(WINDOWS_LOG_TYPE);
        long templateStartTime = ((Number) template.get("start_time")).longValue();

        int copies = 10000;
        Map<String, Long> startTimes = new HashMap<>();
        Map<String, String> severities = new HashMap<>();
        for (String id : fixture.alertDocs.keySet()) {
            startTimes.put(id, ((Number) fixture.alertDocs.get(id).get("start_time")).longValue());
            severities.put(id, (String) fixture.alertDocs.get(id).get("severity"));
        }
        StringBuilder bulk = new StringBuilder();
        for (int i = 0; i < copies; i++) {
            Map<String, Object> copy = new HashMap<>(template);
            String id = "bulk_alert_" + i;
            String severity = i % 2 == 0 ? "5" : "1";
            // pairs of alerts tie on the start time, one of them in the history index
            long startTime = templateStartTime - (i / 2) - 1;
            copy.put("severity", severity);
            copy.put("start_time", startTime);
            startTimes.put(id, startTime);
            severities.put(id, severity);
            bulk.append("{ \"index\": { \"_index\": \"").append(i % 3 == 0 ? historyIndex : activeIndex).append("\", \"_id\": \"")
                    .append(id).append("\", \"routing\": \"").append(fixture.windowsMonitorId).append("\" } }\n");
            bulk.append(org.opensearch.common.xcontent.XContentFactory.jsonBuilder().map(copy).toString()).append('\n');
        }
        Request bulkRequest = new Request("POST", "_bulk");
        bulkRequest.addParameter("refresh", "true");
        bulkRequest.setJsonEntity(bulk.toString());
        assertEquals(Boolean.FALSE, entityAsMap(performAsAdmin(bulkRequest)).get("errors"));
        Set<String> allIds = new HashSet<>(startTimes.keySet());
        int totalAlerts = copies + 14;
        assertEquals(totalAlerts, allIds.size());

        // offset paging is unchanged: the total is capped at 10,000 and pages end within the max result window
        Map<String, Object> offsetPage = getAlertsApi(client(), params("size", "0"));
        assertEquals(Set.of("alerts", "total_alerts"), offsetPage.keySet());
        assertEquals(10000, offsetPage.get("total_alerts"));
        assertBadRequest(params("startIndex", "9991", "size", "10"), "Result window is too large");
        // cursor paging: the exact total, also for offset pages
        assertEquals(totalAlerts, total(cursorPage(client(), params("size", "0"))));
        assertEquals(copies / 2, total(cursorPage(client(), params("size", "0", "severityLevels", "5"))));
        assertEquals(copies / 2 + 4, total(cursorPage(client(), params("size", "0", "severityLevel", "1"))));
        assertBadRequest(params("paging", "cursor", "startIndex", "9991", "size", "10"), "Result window is too large");

        Map<String, String> byStartTime = params("sortString", "start_time", "sortOrder", "desc");
        List<Map<String, Object>> pages = walkNext(client(), byStartTime, 1000, totalAlerts);
        assertEquals(11, pages.size());
        assertEquals(14, alertIdsOf(pages.get(10)).size());
        List<String> walked = ids(pages);
        assertNoDuplicates(walked);
        assertEquals(allIds, Set.copyOf(walked));
        for (int i = 1; i < walked.size(); i++) {
            assertTrue(walked.get(i - 1) + " before " + walked.get(i),
                    startTimes.get(walked.get(i - 1)) >= startTimes.get(walked.get(i)));
        }
        for (Map<String, Object> alert : alertsOf(pages.get(10))) {
            String id = (String) alert.get("id");
            assertEquals(fixture.detectorIdOf(id.startsWith("bulk_alert_") ? windowsAlertId : id), alert.get("detector_id"));
        }

        // the first 10,000 alerts are those of offset paging, in the same order (same sort and tie-breakers)
        List<String> offsetIds = new ArrayList<>();
        for (int startIndex = 0; startIndex < 10000; startIndex += 1000) {
            Map<String, String> offsetParams = with(byStartTime, "startIndex", String.valueOf(startIndex), "size", "1000");
            offsetIds.addAll(alertIdsOf(getAlertsApi(client(), offsetParams)));
            Map<String, Object> cursorOffsetPage = cursorPage(client(), offsetParams);
            assertEquals(alertIdsOf(pages.get(startIndex / 1000)), alertIdsOf(cursorOffsetPage));
            // an offset page's cursors continue with the pages of the walk
            assertEquals(alertIdsOf(pages.get(startIndex / 1000 + 1)), alertIdsOf(cursorPage(client(),
                    with(byStartTime, "size", "1000", "searchAfter", nextCursor(cursorOffsetPage)))));
            if (startIndex > 0) {
                assertEquals(alertIdsOf(pages.get(startIndex / 1000 - 1)), alertIdsOf(cursorPage(client(),
                        with(byStartTime, "size", "1000", "searchAfter", prevCursor(cursorOffsetPage), "direction", "prev"))));
            } else {
                assertNull(prevCursor(cursorOffsetPage));
            }
        }
        assertEquals(walked.subList(0, 10000), offsetIds);

        // the walk is stable
        assertEquals(walked, ids(walkNext(client(), byStartTime, 1000, totalAlerts)));

        // prev returns exactly the previous page, also beyond the max result window
        for (int k : new int[] { 1, 5, 10 }) {
            Map<String, Object> previous = cursorPage(client(),
                    with(byStartTime, "size", "1000", "searchAfter", prevCursor(pages.get(k)), "direction", "prev"));
            assertEquals("page " + k, alertIdsOf(pages.get(k - 1)), alertIdsOf(previous));
            assertEquals(totalAlerts, total(previous));
            if (k == 1) {
                assertNull(prevCursor(previous));
            } else {
                assertNotNull(prevCursor(previous));
            }
            // and next from it returns the page again
            assertEquals(alertIdsOf(pages.get(k)), alertIdsOf(cursorPage(client(),
                    with(byStartTime, "size", "1000", "searchAfter", nextCursor(previous)))));
        }
        // walking back from the last page gives the same pages
        assertEquals(pageIds(pages), pageIds(walkPrev(client(), byStartTime, 1000, pages.get(10))));

        // other sorts and page sizes beyond the max result window
        List<String> bySeverity = ids(walkNext(client(), params("sortString", "severity", "sortOrder", "asc"), 999, totalAlerts));
        assertNoDuplicates(bySeverity);
        assertEquals(allIds, Set.copyOf(bySeverity));
        for (int i = 1; i < bySeverity.size(); i++) {
            String previous = bySeverity.get(i - 1);
            String current = bySeverity.get(i);
            int bySeverityOrder = severities.get(previous).compareTo(severities.get(current));
            assertTrue(previous + " before " + current, bySeverityOrder < 0
                    || (bySeverityOrder == 0 && startTimes.get(previous) >= startTimes.get(current)));
        }
        // filters apply to every page
        List<String> severity5 = ids(walkNext(client(), params("severityLevels", "5", "sortString", "state"), 1000, copies / 2));
        assertNoDuplicates(severity5);
        assertTrue(severity5.stream().allMatch(id -> "5".equals(severities.get(id))));
        assertEquals(copies / 2, severity5.size());
    }

    /**
     * Every sort field and order, with alerts tying on the sort field and in the active and history alert indices of
     * both log types: cursor pages of any size are exactly the alerts of offset paging, in the same order, both
     * walking forward and backward.
     */
    public void testCursorPaging_everySortFieldAndOrder() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        long endTime = System.currentTimeMillis();
        moveAlertToHistory(fixture, sorted(fixture.windowsAlertIds()).get(1), WINDOWS_LOG_TYPE, endTime);
        moveAlertToHistory(fixture, sorted(fixture.networkAlertIds()).get(1), NETWORK_LOG_TYPE, endTime);
        reloadAlertDocs(fixture);
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());

        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            for (String sortOrder : List.of("asc", "desc", "DESC")) {
                Map<String, String> sortParams = params("sortString", sortString, "sortOrder", sortOrder);
                List<String> offsetIds = alertIdsOf(getAlertsApi(client(), with(sortParams, "size", "100")));
                assertEquals(allIds, Set.copyOf(offsetIds));
                for (int size : new int[] { 1, 3, 5, 14, 20 }) {
                    String description = sortString + " " + sortOrder + " size " + size;
                    List<Map<String, Object>> pages = walkNext(client(), sortParams, size, 14);
                    assertEquals(description, offsetIds, ids(pages));
                    assertEquals(description, (14 + size - 1) / size, pages.size());
                    assertEquals(description, pageIds(pages), pageIds(walkPrev(client(), sortParams, size, pages.get(pages.size() - 1))));
                    // a cursor page's prev cursor leads back to the previous page
                    for (int k = 1; k < pages.size(); k++) {
                        assertEquals(description, alertIdsOf(pages.get(k - 1)), alertIdsOf(cursorPage(client(),
                                with(sortParams, "size", String.valueOf(size), "searchAfter", prevCursor(pages.get(k)), "direction", "prev"))));
                    }
                }
                // the last alert, and past it: an empty page without cursors
                Map<String, Object> last = cursorPage(client(), with(sortParams, "size", "13", "searchAfter",
                        nextCursor(cursorPage(client(), with(sortParams, "size", "13")))));
                assertEquals(List.of(offsetIds.get(13)), alertIdsOf(last));
                assertNull(nextCursor(last));
                Map<String, Object> pastLast = cursorPage(client(), with(sortParams, "size", "13", "searchAfter", prevCursor(last)));
                assertEquals(List.of(), alertIdsOf(pastLast));
                assertEquals(14L, total(pastLast));
                assertNull(nextCursor(pastLast));
                assertNull(prevCursor(pastLast));
                // the first alert, from the second one
                Map<String, Object> beforeFirst = cursorPage(client(), with(sortParams, "size", "5", "searchAfter",
                        prevCursor(cursorPage(client(), with(sortParams, "size", "5", "startIndex", "1"))), "direction", "prev"));
                assertEquals(List.of(offsetIds.get(0)), alertIdsOf(beforeFirst));
                assertNull(prevCursor(beforeFirst));
                assertNotNull(nextCursor(beforeFirst));
            }
        }
    }

    /**
     * The filters, the search string and the time range apply to cursor pages as to offset pages, for the alerts of
     * all detectors, a detector type and a detector id.
     */
    public void testCursorPaging_filtersEqualOffsetPaging() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        List<Long> startTimes = new ArrayList<>();
        fixture.alertDocs.values().forEach(doc -> startTimes.add(((Number) doc.get("start_time")).longValue()));
        Collections.sort(startTimes);
        String from = String.valueOf(startTimes.get(3));
        String to = String.valueOf(startTimes.get(10));

        List<Map<String, String>> filters = List.of(
                Map.of(),
                params("severityLevels", "1,2"),
                params("severityLevels", "3"),
                params("severityLevel", "4"),
                params("alertStates", "ACTIVE"),
                params("alertState", "ACTIVE"),
                params("alertStates", "COMPLETED"),
                params("searchString", WINDOWS_DETECTOR_NAME),
                params("searchString", "wintrigone OR nettrigtwo"),
                params("searchString", "net*"),
                params("startTime", from, "endTime", to),
                params("startTime", from, "endTime", to, "severityLevels", "1,4", "searchString", "wintrigone OR nettrigfour")
        );
        for (Map<String, String> filter : filters) {
            for (String sortString : List.of("start_time", "severity")) {
                Map<String, String> request = with(filter, "sortString", sortString, "sortOrder", "desc");
                Map<String, Object> offset = getAlertsApi(client(), with(request, "size", "100"));
                List<String> offsetIds = alertIdsOf(offset);
                int total = (Integer) offset.get("total_alerts");
                assertEquals(request.toString(), offsetIds, ids(walkNext(client(), request, 2, total)));
            }
        }

        // a detector type and a detector id: their offset pages are served by Alerting, without tie-breakers, so only
        // the alerts, the totals and the sort field's order are compared
        for (Map<String, String> filter : filters) {
            for (Map<String, String> detector : List.of(params("detectorType", WINDOWS_LOG_TYPE), params("detector_id", fixture.networkDetectorId),
                    params("detector_id", fixture.windowsDetectorId))) {
                Map<String, String> request = with(filter, "sortString", "severity", "sortOrder", "asc");
                request.putAll(detector);
                Map<String, Object> offset = getAlertsApi(client(), with(request, "size", "100"));
                int total = (Integer) offset.get("total_alerts");
                List<String> walked = ids(walkNext(client(), request, 3, total));
                assertNoDuplicates(walked);
                assertEquals(request.toString(), Set.copyOf(alertIdsOf(offset)), Set.copyOf(walked));
                assertEquals(request.toString(), sortValues(fixture, alertIdsOf(offset), "severity", "asc"),
                        sortValues(fixture, walked, "severity", "asc"));
                String expectedDetectorId = detector.containsKey("detector_id") ? detector.get("detector_id") : fixture.windowsDetectorId;
                for (Map<String, Object> page : walkNext(client(), request, 3, total)) {
                    for (Map<String, Object> alert : alertsOf(page)) {
                        assertEquals(expectedDetectorId, alert.get("detector_id"));
                    }
                }
            }
        }
        // the same errors as offset paging
        for (Map<String, String> request : List.of(params("detectorType", "linux"), params("detector_id", "no_such_detector"))) {
            assertEquals(request.toString(), status(request), status(with(request, "paging", "cursor")));
            assertNotEquals(RestStatus.OK.getStatus(), status(with(request, "paging", "cursor")));
        }
        assertEquals(RestStatus.NOT_FOUND.getStatus(), status(params("paging", "cursor", "detectorType", "linux")));
        // a detector without monitors has no alerts
        indexCopyOfDetectorWithoutMonitors(fixture.windowsDetectorId, "detector_without_monitors", "windetectorcopy");
        Map<String, Object> empty = cursorPage(client(), params("detector_id", "detector_without_monitors"));
        assertEquals(List.of(), empty.get("alerts"));
        assertEquals(0L, total(empty));
        assertNull(nextCursor(empty));
        assertNull(prevCursor(empty));
    }

    public void testCursorPaging_noDetectors() throws IOException {
        Map<String, Object> body = cursorPage(client(), Map.of());
        assertEquals(List.of(), body.get("alerts"));
        assertEquals(0L, total(body));
        assertNull(nextCursor(body));
        assertNull(prevCursor(body));
    }

    /**
     * Alerting's own alerts, alerts of monitors that are no detector's, and correlation and threat intel alerts are
     * never returned in cursor paging, also when partial search results are not allowed.
     */
    public void testCursorPaging_excludesAlertsNotGeneratedByVisibleDetectors() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        String alertingMonitorName = "plainalertingmonitor";
        List<String> alertingAlertIds = createAlertingMonitorWithAlert(alertingMonitorName, WINDOWS_INDEX);
        Map<String, Object> foreignAlert = new HashMap<>(fixture.alertDocs.get(fixture.windowsAlertIds().iterator().next()));
        foreignAlert.remove("_id");
        foreignAlert.remove("_index");
        foreignAlert.put("monitor_id", "foreign_monitor_id");
        indexDocAsAdmin(DetectorMonitorConfig.getAlertsIndex(WINDOWS_LOG_TYPE), "foreign_alert_id", "foreign_monitor_id", foreignAlert);
        createCorrelationAndThreatIntelAlerts();

        for (Boolean allowPartialResults : new Boolean[] { null, false }) {
            setDefaultAllowPartialSearchResults(allowPartialResults);
            try {
                for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
                    List<String> walked = ids(walkNext(client(), params("sortString", sortString), 4, 14));
                    assertNoDuplicates(walked);
                    assertEquals(allIds, Set.copyOf(walked));
                }
                assertEquals(fixture.windowsAlertIds(), Set.copyOf(ids(walkNext(client(),
                        params("searchString", WINDOWS_DETECTOR_NAME), 3, 8))));
                assertEquals(List.of(), alertIdsOf(cursorPage(client(), params("searchString", alertingMonitorName))));
                assertEquals(fixture.windowsAlertIds(), Set.copyOf(ids(walkNext(client(),
                        params("detector_id", fixture.windowsDetectorId), 3, 8))));
                assertEquals(fixture.windowsAlertIds(), Set.copyOf(ids(walkNext(client(),
                        params("detectorType", WINDOWS_LOG_TYPE), 3, 8))));
                assertTrue(Collections.disjoint(alertingAlertIds, ids(walkNext(client(), params("size", "100"), 100, 14))));
            } finally {
                setDefaultAllowPartialSearchResults(null);
            }
        }
    }

    public void testCursorPaging_invalidRequests_return400() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Map<String, Object> first = cursorPage(client(), params("size", "5", "sortString", "severity", "sortOrder", "desc"));
        String cursor = nextCursor(first);
        assertNotNull(cursor);
        Map<String, String> base = params("paging", "cursor", "sortString", "severity", "sortOrder", "desc", "size", "5");
        assertEquals(5, alertIdsOf(getAlertsApi(client(), with(base, "searchAfter", cursor))).size());

        // a tampered cursor
        char flipped = cursor.charAt(3) == 'A' ? 'B' : 'A';
        String tampered = cursor.substring(0, 3) + flipped + cursor.substring(4);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), status(with(base, "searchAfter", tampered)));
        assertBadRequest(with(base, "searchAfter", cursor + "x!"), "searchAfter is not a valid cursor");
        assertBadRequest(with(base, "searchAfter", "eyJ2IjoxfQ"), "searchAfter is not a valid cursor");
        assertBadRequest(with(base, "searchAfter", "eyJ2IjoyLCJmIjoic2V2ZXJpdHkiLCJvIjoiZGVzYyIsIm0iOm51bGwsImsiOltdfQ"),
                "unsupported version");
        // a cursor of another sort
        assertBadRequest(with(base, "searchAfter", cursor, "sortOrder", "asc"), "not of the requested sort");
        assertBadRequest(with(base, "searchAfter", cursor, "sortString", "state"), "not of the requested sort");
        // startIndex with a cursor
        assertBadRequest(with(base, "searchAfter", cursor, "startIndex", "5"), "startIndex cannot be used with searchAfter");
        assertBadRequest(with(base, "searchAfter", cursor, "startIndex", "0"), "startIndex cannot be used with searchAfter");
        // size, direction and paging values
        assertBadRequest(with(base, "searchAfter", cursor, "size", "0"), "size must be between 1 and 1000 with searchAfter");
        assertBadRequest(with(base, "size", "1001"), "size must be between 0 and 1000");
        assertBadRequest(with(base, "direction", "sideways"), "direction [sideways] is not supported");
        assertBadRequest(with(base, "direction", "prev"), "direction [prev] requires searchAfter");
        assertBadRequest(with(base, "paging", "offset"), "paging [offset] is not supported, supported values are [cursor]");
        assertBadRequest(with(base, "sortString", "trigger_name"), "sortString [trigger_name] is not supported");
        assertBadRequest(with(base, "detector_id", fixture.windowsDetectorId, "sortString", "trigger_name"),
                "sortString [trigger_name] is not supported");
        assertBadRequest(with(base, "alertStates", "AUDIT"), "contains invalid values [AUDIT]");
        assertBadRequest(with(base, "searchString", "a:("), "is not a valid query string");
        // the cursor paging params are not recognized without paging, as before
        assertBadRequest(params("searchAfter", cursor), "unrecognized parameter");
        assertBadRequest(params("direction", "next"), "unrecognized parameter");
    }

    /** Requests without paging are served as before: same response fields, totals capped at 10,000. */
    public void testRequestsWithoutPaging_unchanged() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        for (Map<String, String> request : List.of(Map.<String, String>of(), params("detector_id", fixture.windowsDetectorId),
                params("detectorType", NETWORK_LOG_TYPE), params("size", "3", "startIndex", "3"))) {
            Map<String, Object> body = getAlertsApi(client(), request);
            assertEquals(request.toString(), Set.of("alerts", "total_alerts"), body.keySet());
        }
        assertAlerts(fixture, getAlertsApi(client(), Map.of()), union(fixture.windowsAlertIds(), fixture.networkAlertIds()));
        // offset paging of a detector id still sorts on any alert field (through Alerting), unlike cursor paging
        assertEquals(8, alertIdsOf(getAlertsApi(client(), params("detector_id", fixture.windowsDetectorId,
                "sortString", "trigger_name.keyword"))).size());
    }

    /** The history alert index Alerting created for the log type */
    @SuppressWarnings("unchecked")
    private String historyIndex(String logType) throws IOException {
        Request getHistoryIndices = new Request("GET", "_cat/indices/" + DetectorMonitorConfig.getAlertsHistoryIndex(logType) + "-*");
        getHistoryIndices.addParameter("format", "json");
        getHistoryIndices.addParameter("expand_wildcards", "all");
        getHistoryIndices.addParameter("h", "index");
        List<Map<String, Object>> historyIndices = (List<Map<String, Object>>) (List<?>) entityAsList(performAsAdmin(getHistoryIndices));
        assertFalse("no alert history index of " + logType, historyIndices.isEmpty());
        return historyIndices.stream().map(index -> (String) index.get("index")).sorted().findFirst().orElseThrow();
    }
}
