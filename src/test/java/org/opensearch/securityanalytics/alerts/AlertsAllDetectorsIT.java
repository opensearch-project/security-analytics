/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.util.CorrelationIndices;

import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomNetworkDoc;

/**
 * GET _plugins/_security_analytics/alerts without detector_id and detectorType returns the alerts of all detectors.
 */
public class AlertsAllDetectorsIT extends AlertsAllDetectorsTestCase {

    public void testGetAlertsWithoutDetector_noDetectors_returnsEmpty() throws IOException {
        Map<String, Object> body = getAlertsApi(client(), Map.of());
        assertEquals(List.of(), body.get("alerts"));
        assertEquals(0, body.get("total_alerts"));

        // detectors index exists, but no detector has monitors
        createLogIndices();
        String detectorId = createWindowsDetector(client(), WINDOWS_DETECTOR_NAME);
        indexCopyOfDetectorWithoutMonitors(detectorId, "copy_without_monitors", "copywithoutmonitors");
        deleteDetector(detectorId);
        body = getAlertsApi(client(), params("size", "0"));
        assertEquals(List.of(), body.get("alerts"));
        assertEquals(0, body.get("total_alerts"));
    }

    public void testGetAlertsWithoutDetector_returnsAlertsOfAllDetectors() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());

        // no detector id / type, default page size 20 > 14 alerts
        assertAlerts(fixture, getAlertsApi(client(), Map.of()), allIds);
        assertAlerts(fixture, getAlertsApi(client(), params("detector_id", "")), allIds);

        // detector_id and detectorType keep returning the alerts of the detector / log type only
        assertAlerts(fixture, getAlertsApi(client(), params("detector_id", fixture.windowsDetectorId)), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("detector_id", fixture.networkDetectorId)), fixture.networkAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("detectorType", WINDOWS_LOG_TYPE)), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("detectorType", NETWORK_LOG_TYPE)), fixture.networkAlertIds());
        ResponseException e = expectThrows(ResponseException.class,
                () -> getAlertsApi(client(), params("detectorType", "linux")));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    @SuppressWarnings("unchecked")
    public void testGetAlertsWithoutDetector_excludesAlertsNotGeneratedByVisibleDetectors() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());

        // 1. an Alerting plugin monitor (not a detector monitor) with an alert in Alerting's own alert indices
        String alertingMonitorName = "plainalertingmonitor";
        List<String> alertingAlertIds = createAlertingMonitorWithAlert(alertingMonitorName, WINDOWS_INDEX);

        // 2. an alert of a monitor that does not belong to any detector, stored in a detector alert index; it matches
        // the windows detector's name, trigger, severity and time range so only the monitor filter can exclude it
        Map<String, Object> foreignAlert = new HashMap<>(fixture.alertDocs.get(fixture.windowsAlertIds().iterator().next()));
        foreignAlert.remove("_id");
        foreignAlert.remove("_index");
        foreignAlert.put("monitor_id", "foreign_monitor_id");
        indexDocAsAdmin(DetectorMonitorConfig.getAlertsIndex(WINDOWS_LOG_TYPE), "foreign_alert_id", "foreign_monitor_id", foreignAlert);

        // 3. a detector of the same log type without monitors
        indexCopyOfDetectorWithoutMonitors(fixture.windowsDetectorId, "detector_without_monitors", "windetectorcopy");

        // 4. correlation and threat intel alerts, whose indices also match .opensearch-sap-*-alerts*
        createCorrelationAndThreatIntelAlerts();

        Set<String> excludedIds = new java.util.HashSet<>(alertingAlertIds);
        excludedIds.add("foreign_alert_id");
        excludedIds.add("correlation_alert_id");
        excludedIds.add("threat_intel_alert_id");

        List<Map<String, String>> requests = List.of(
                Map.of(),
                params("size", "100"),
                params("detectorType", WINDOWS_LOG_TYPE, "size", "100"),
                params("detector_id", fixture.windowsDetectorId, "size", "100"),
                params("searchString", alertingMonitorName),
                params("searchString", alertingMonitorName, "detectorType", WINDOWS_LOG_TYPE),
                params("searchString", alertingMonitorName, "detector_id", fixture.windowsDetectorId),
                params("searchString", WINDOWS_DETECTOR_NAME, "size", "100"),
                params("searchString", WINDOWS_DETECTOR_NAME, "detectorType", WINDOWS_LOG_TYPE),
                params("searchString", WINDOWS_DETECTOR_NAME, "detector_id", fixture.windowsDetectorId),
                params("severityLevels", "1", "alertStates", "ACTIVE", "size", "100")
        );
        for (Map<String, String> request : requests) {
            Map<String, Object> body = getAlertsApi(client(), request);
            List<String> ids = alertIdsOf(body);
            for (String excludedId : excludedIds) {
                assertFalse(request + " returned excluded alert " + excludedId, ids.contains(excludedId));
            }
            assertTrue(request + " returned " + ids, allIds.containsAll(ids));
        }
        assertAlerts(fixture, getAlertsApi(client(), Map.of()), allIds);
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", alertingMonitorName)), Set.of());
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", WINDOWS_DETECTOR_NAME)), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("detectorType", WINDOWS_LOG_TYPE)), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("detector_id", "detector_without_monitors")), Set.of());

        // the excluded alerts do exist
        assertEquals(1, executeSearch(DetectorMonitorConfig.getAlertsIndex(WINDOWS_LOG_TYPE),
                "{ \"query\": { \"ids\": { \"values\": [\"foreign_alert_id\"] } } }").size());
    }

    public void testGetAlertsWithoutDetector_sortingAndPaging() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> historyIds = acknowledgeAndCompleteAlerts(fixture);
        // their indices match .opensearch-sap-*-alerts* but do not map all alert fields
        createCorrelationAndThreatIntelAlerts();
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        // Searching indices that do not map the sort field fails those shards. Disallow partial results so that such
        // shard failures fail the request instead of being silently ignored.
        setDefaultAllowPartialSearchResults(false);
        try {
            assertSortingAndPaging(fixture, allIds, historyIds);
        } finally {
            setDefaultAllowPartialSearchResults(null);
        }
    }

    /**
     * Acknowledges an alert of each detector and moves another alert of each detector, as COMPLETED, to its log type's
     * alert history index, so that the alerts have three different states and are stored in active and history
     * indices. Reloads the fixture.
     *
     * @return the ids of the alerts in the history indices
     */
    private Set<String> acknowledgeAndCompleteAlerts(AlertsFixture fixture) throws Exception {
        List<String> windowsIds = sorted(fixture.windowsAlertIds());
        List<String> networkIds = sorted(fixture.networkAlertIds());
        acknowledgeAlert(windowsIds.get(0), fixture.windowsDetectorId);
        acknowledgeAlert(networkIds.get(0), fixture.networkDetectorId);
        reloadAlertDocs(fixture);
        long endTime = System.currentTimeMillis();
        moveAlertToHistory(fixture, windowsIds.get(1), WINDOWS_LOG_TYPE, endTime);
        moveAlertToHistory(fixture, networkIds.get(1), NETWORK_LOG_TYPE, endTime + 1000);
        reloadAlertDocs(fixture);

        Set<String> historyIds = Set.of(windowsIds.get(1), networkIds.get(1));
        for (String alertId : fixture.alertDocs.keySet()) {
            Map<String, Object> alertDoc = fixture.alertDocs.get(alertId);
            String logType = fixture.detectorIdOf(alertId).equals(fixture.windowsDetectorId) ? WINDOWS_LOG_TYPE : NETWORK_LOG_TYPE;
            String index = (String) alertDoc.get("_index");
            boolean inHistory = index.startsWith(DetectorMonitorConfig.getAlertsHistoryIndex(logType) + "-");
            if (historyIds.contains(alertId)) {
                assertTrue(alertDoc.toString(), inHistory);
                assertEquals("COMPLETED", alertDoc.get("state"));
            } else if (alertId.equals(windowsIds.get(0)) || alertId.equals(networkIds.get(0))) {
                // Alerting may move acknowledged alerts to the history index too
                assertTrue(alertDoc.toString(), inHistory || index.equals(DetectorMonitorConfig.getAlertsIndex(logType)));
                assertEquals("ACKNOWLEDGED", alertDoc.get("state"));
            } else {
                assertEquals(DetectorMonitorConfig.getAlertsIndex(logType), index);
                assertEquals("ACTIVE", alertDoc.get("state"));
            }
        }
        return historyIds;
    }

    private void assertSortingAndPaging(AlertsFixture fixture, Set<String> allIds, Set<String> historyIds) throws IOException {
        assertEquals(List.of("start_time", "monitor_name.keyword", "state", "severity"), GetAlertsRequest.SORTABLE_FIELDS);
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            for (String sortOrder : List.of("asc", "desc", "DESC")) {
                Map<String, String> sortParams = params("sortString", sortString, "sortOrder", sortOrder);
                Map<String, String> fullParams = new HashMap<>(sortParams);
                fullParams.put("size", "100");
                Map<String, Object> full = getAlertsApi(client(), fullParams);
                assertAlerts(fixture, full, allIds);
                List<String> fullIds = alertIdsOf(full);
                assertEquals(sortString + " " + sortOrder, expectedSortValues(fixture, allIds, sortString, sortOrder),
                        sortValues(fixture, fullIds, sortString, sortOrder));
                // the completed alerts in the history indices of both log types are included in the pages and totals
                assertTrue(fullIds + " lacks " + historyIds, fullIds.containsAll(historyIds));
                Map<String, String> completedParams = new HashMap<>(fullParams);
                completedParams.put("alertStates", "COMPLETED");
                Map<String, Object> completed = getAlertsApi(client(), completedParams);
                assertAlerts(fixture, completed, historyIds);
                assertEquals(expectedSortValues(fixture, historyIds, sortString, sortOrder),
                        sortValues(fixture, alertIdsOf(completed), sortString, sortOrder));

                // paging: concatenated pages are the full sorted result, without duplicates or gaps
                assertEquals(fullIds, fetchAllPages(client(), sortParams, 3, 14));
                assertEquals(fullIds, fetchAllPages(client(), sortParams, 7, 14));
                assertEquals(fullIds, fetchAllPages(client(), sortParams, 14, 14));

                // size=0 returns only the total, a start index beyond the total returns no alerts
                for (String startIndex : List.of("14", "15", "100")) {
                    Map<String, String> beyond = new HashMap<>(sortParams);
                    beyond.put("startIndex", startIndex);
                    Map<String, Object> body = getAlertsApi(client(), beyond);
                    assertEquals(List.of(), body.get("alerts"));
                    assertEquals(14, body.get("total_alerts"));
                }
                Map<String, String> totalOnly = new HashMap<>(sortParams);
                totalOnly.put("size", "0");
                Map<String, Object> body = getAlertsApi(client(), totalOnly);
                assertEquals(List.of(), body.get("alerts"));
                assertEquals(14, body.get("total_alerts"));
            }
        }

        // the monitors ran alternately, so sorted by start time the alerts of the two detectors interleave
        List<String> byStartTime = alertIdsOf(getAlertsApi(client(), params("sortString", "start_time", "size", "100")));
        int detectorChanges = 0;
        for (int i = 1; i < byStartTime.size(); i++) {
            if (fixture.detectorIdOf(byStartTime.get(i)).equals(fixture.detectorIdOf(byStartTime.get(i - 1))) == false) {
                detectorChanges++;
            }
        }
        assertEquals(byStartTime.toString(), 3, detectorChanges);

        // same sort and paging for a detector type, which is served by Alerting
        Map<String, String> windowsParams = params("detectorType", WINDOWS_LOG_TYPE, "sortString", "trigger_name.keyword", "sortOrder", "desc");
        Map<String, String> windowsFull = new HashMap<>(windowsParams);
        windowsFull.put("size", "100");
        List<String> windowsIds = alertIdsOf(getAlertsApi(client(), windowsFull));
        assertEquals(expectedSortValues(fixture, fixture.windowsAlertIds(), "trigger_name.keyword", "desc"),
                sortValues(fixture, windowsIds, "trigger_name.keyword", "desc"));
        assertEquals(windowsIds, fetchAllPages(client(), windowsParams, 3, 8));

        // a page beyond the max result window is a client error
        for (Map<String, String> request : List.of(params("startIndex", "9995", "size", "10"),
                params("detectorType", WINDOWS_LOG_TYPE, "startIndex", "9995", "size", "10"))) {
            ResponseException e = expectThrows(ResponseException.class, () -> getAlertsApi(client(), request));
            assertEquals(request.toString(), RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
            assertTrue(responseBody(e), responseBody(e).contains("Result window is too large"));
        }
    }

    public void testGetAlertsWithoutDetector_filters() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());

        // acknowledge two windows alerts and one network alert
        List<String> acknowledged = new ArrayList<>();
        acknowledged.addAll(sorted(fixture.windowsAlertIds()).subList(0, 2));
        acknowledged.add(sorted(fixture.networkAlertIds()).get(0));
        for (String alertId : acknowledged) {
            acknowledgeAlert(alertId, fixture.detectorIdOf(alertId));
        }
        Set<String> acknowledgedIds = Set.copyOf(acknowledged);
        Set<String> activeIds = allIds.stream().filter(id -> acknowledgedIds.contains(id) == false).collect(Collectors.toSet());

        // alert states
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "ACKNOWLEDGED")), acknowledgedIds);
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "acknowledged")), acknowledgedIds);
        assertAlerts(fixture, getAlertsApi(client(), params("alertState", "ACKNOWLEDGED")), acknowledgedIds);
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "ACTIVE")), activeIds);
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "ACTIVE,ACKNOWLEDGED")), allIds);
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "COMPLETED,ERROR")), Set.of());
        assertAlerts(fixture, getAlertsApi(client(), params("alertStates", "ACKNOWLEDGED", "detector_id", fixture.windowsDetectorId)),
                Set.copyOf(acknowledged.subList(0, 2)));

        // severities: windows alerts have severity 1 and 3, network alerts 2 and 4
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "1,2")), withSeverity(fixture, allIds, "1", "2"));
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "3")), withSeverity(fixture, allIds, "3"));
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevel", "4")), withSeverity(fixture, allIds, "4"));
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "1, 2,3,4")), allIds);
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "5")), Set.of());
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "1,3", "detectorType", NETWORK_LOG_TYPE)), Set.of());
        assertEquals(4, withSeverity(fixture, allIds, "1").size());
        assertEquals(3, withSeverity(fixture, allIds, "2").size());

        // severity and state together
        Set<String> severity1Or4Acknowledged = withSeverity(fixture, acknowledgedIds, "1", "4");
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevels", "1,4", "alertStates", "ACKNOWLEDGED")), severity1Or4Acknowledged);
        assertAlerts(fixture, getAlertsApi(client(), params("severityLevel", "3", "alertStates", "ACTIVE,ACKNOWLEDGED")),
                withSeverity(fixture, allIds, "3"));

        // search string on monitor (= detector) and trigger names
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", NETWORK_DETECTOR_NAME)), fixture.networkAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", "wintrigone")), withSeverity(fixture, allIds, "1"));
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", "nettrig*")), fixture.networkAlertIds());
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", "*trigfour")), withSeverity(fixture, allIds, "4"));
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", "netdetector AND nettrigtwo")), withSeverity(fixture, allIds, "2"));
        assertAlerts(fixture, getAlertsApi(client(), params("searchString", "unknowndetector")), Set.of());

        // time range on start_time (inclusive), taken from the second half of the generated alerts
        List<Long> startTimes = allIds.stream().map(id -> startTime(fixture, id)).sorted().collect(Collectors.toList());
        long from = startTimes.get(startTimes.size() / 2);
        long to = startTimes.get(startTimes.size() - 1);
        Set<String> inRange = allIds.stream().filter(id -> startTime(fixture, id) >= from && startTime(fixture, id) <= to).collect(Collectors.toSet());
        assertFalse(inRange.isEmpty());
        assertTrue(inRange.size() < allIds.size());
        assertAlerts(fixture, getAlertsApi(client(), params("startTime", String.valueOf(from), "endTime", String.valueOf(to))), inRange);
        assertAlerts(fixture, getAlertsApi(client(), params("startTime", String.valueOf(to + 1), "endTime", String.valueOf(to + 100000))), Set.of());
        Set<String> inRangeAndSeverity3 = withSeverity(fixture, inRange, "3");
        assertAlerts(fixture, getAlertsApi(client(), params("startTime", String.valueOf(from), "endTime", String.valueOf(to),
                "severityLevels", "3")), inRangeAndSeverity3);
    }

    public void testGetAlerts_invalidParameters_return400() throws Exception {
        // the sort field of alerts of all detectors is validated, independently of the detectors that exist
        for (String sortString : List.of("end_time", "last_notification_time", "acknowledged_time", "trigger_name.keyword", "workflow_id",
                "monitor_id", "schema_version", "monitor_name", "trigger_name", "foo", "id", "version", "error_message",
                "alert_history.timestamp")) {
            assertBadRequest(Map.of(), params("sortString", sortString), "sortString [" + sortString
                    + "] is not supported, supported values are [start_time, monitor_name.keyword, state, severity]");
        }
        // validation happens before any detector is looked up, in every mode
        for (Map<String, String> base : List.of(Map.<String, String>of(), params("detectorType", WINDOWS_LOG_TYPE),
                params("detector_id", "nonexistent_detector_id"))) {
            assertBadRequest(base, params("sortOrder", "up"), "sortOrder [up] is not supported");
            assertBadRequest(base, params("alertStates", "ACTIVE,FOO"), "contains invalid values [FOO]");
            assertBadRequest(base, params("alertStates", "ALL"), "contains invalid values [ALL]");
            assertBadRequest(base, params("alertStates", "AUDIT"), "contains invalid values [AUDIT]");
            assertBadRequest(base, params("alertStates", "ACTIVE,AUDIT"), "contains invalid values [AUDIT]");
            assertBadRequest(base, params("severityLevels", "ALL"), "must not contain blank values or [ALL]");
            assertBadRequest(base, params("severityLevel", "1", "severityLevels", "1,2"), "only one of severityLevel and severityLevels");
            assertBadRequest(base, params("alertState", "ACTIVE", "alertStates", "ACTIVE"), "only one of alertState and alertStates");
            assertBadRequest(base, params("searchString", "(foo"), "searchString [(foo] is not a valid query string");
            assertBadRequest(base, params("searchString", "foo AND"), "searchString [foo AND] is not a valid query string");
            // invalid and too complex regular expressions are client errors, not internal errors
            assertBadRequest(base, params("searchString", "/[a-/"), "searchString [/[a-/] is not a valid query string");
            assertBadRequest(base, params("searchString", "/[ac]*a[ac]{50,200}/"), "is not a valid query string");
            assertBadRequest(base, params("size", "-1"), "size must be greater than or equal to 0");
            assertBadRequest(base, params("startIndex", "-5"), "startIndex must be greater than or equal to 0");
        }
        // the single value alertState keeps accepting AUDIT
        Map<String, Object> body = getAlertsApi(client(), params("alertState", "AUDIT"));
        assertEquals(0, body.get("total_alerts"));
    }

    /**
     * Alerts of a detector id or a detector type are sorted by Alerting in a single search: like before, they can be
     * sorted on any field of the alert mapping, also on fields alerts of all detectors cannot be sorted on.
     */
    public void testGetAlertsOfDetectorIdAndDetectorType_sortOnAnyAlertField() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        // acknowledged and completed (history) alerts have acknowledged and end times
        acknowledgeAndCompleteAlerts(fixture);
        List<Map<String, String>> modes = List.of(
                params("detector_id", fixture.windowsDetectorId),
                params("detectorType", WINDOWS_LOG_TYPE),
                params("detector_id", fixture.networkDetectorId),
                params("detectorType", NETWORK_LOG_TYPE));
        for (Map<String, String> mode : modes) {
            Set<String> expectedIds = mode.containsValue(fixture.windowsDetectorId) || mode.containsValue(WINDOWS_LOG_TYPE)
                    ? fixture.windowsAlertIds()
                    : fixture.networkAlertIds();
            for (String sortString : List.of("end_time", "acknowledged_time", "last_notification_time", "trigger_name.keyword",
                    "workflow_id", "version", "id", "monitor_id", "schema_version")) {
                for (String sortOrder : List.of("asc", "desc")) {
                    Map<String, String> request = new HashMap<>(mode);
                    request.putAll(params("sortString", sortString, "sortOrder", sortOrder, "size", "100"));
                    Map<String, Object> body = getAlertsApi(client(), request);
                    assertAlerts(fixture, body, expectedIds);
                    if (sortString.equals("version") == false && sortString.equals("id") == false) {
                        assertEquals(request.toString(), expectedSortValues(fixture, expectedIds, sortString, sortOrder),
                                sortValues(fixture, alertIdsOf(body), sortString, sortOrder));
                    }
                }
            }
        }
    }

    /**
     * A detector can be created with a mixed-case detector_type: the create detector API only lowercases it to check
     * that the log type exists, stores it as given, and the detector's alert indices are named after the lowercased log
     * type. Its alerts are returned by detector id, by detectorType (whatever its case) and without detector.
     */
    @SuppressWarnings("unchecked")
    public void testGetAlerts_detectorWithMixedCaseDetectorType() throws Exception {
        String mixedCaseLogType = WINDOWS_LOG_TYPE.substring(0, 1).toUpperCase(Locale.ROOT) + WINDOWS_LOG_TYPE.substring(1);
        assertNotEquals(WINDOWS_LOG_TYPE, mixedCaseLogType);
        createLogIndices();
        AlertsFixture fixture = new AlertsFixture();
        fixture.windowsDetectorId = createDisabledDetector(client(), WINDOWS_DETECTOR_NAME, mixedCaseLogType, WINDOWS_INDEX,
                getRandomPrePackagedRules(), List.of(trigger("wintrigone", "1", WINDOWS_LOG_TYPE)));
        fixture.networkDetectorId = createNetworkDetector(client(), NETWORK_DETECTOR_NAME);
        assertEquals(mixedCaseLogType, ((Map<String, Object>) getDetectorSource(fixture.windowsDetectorId).get("detector")).get("detector_type"));
        fixture.windowsMonitorId = getDetectorMonitorIds(fixture.windowsDetectorId).get(0);
        fixture.networkMonitorId = getDetectorMonitorIds(fixture.networkDetectorId).get(0);

        indexDoc(WINDOWS_INDEX, "1", randomDoc());
        indexDoc(WINDOWS_INDEX, "2", randomDoc());
        assertEquals(2, executeMonitorAndCountAlerts(fixture.windowsMonitorId));
        indexDoc(NETWORK_INDEX, "1", randomNetworkDoc());
        assertEquals(2, executeMonitorAndCountAlerts(fixture.networkMonitorId));
        // the alerts are in the alert indices of the lowercased log type
        for (Map<String, Object> alertDoc : waitForAlertDocs(List.of(WINDOWS_LOG_TYPE, NETWORK_LOG_TYPE),
                List.of(fixture.windowsMonitorId, fixture.networkMonitorId), 4)) {
            fixture.alertDocs.put((String) alertDoc.get("_id"), alertDoc);
        }
        assertEquals(2, fixture.windowsAlertIds().size());
        assertEquals(2, fixture.networkAlertIds().size());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());

        // by detector id (unchanged)
        assertAlerts(fixture, getAlertsApi(client(), params("detector_id", fixture.windowsDetectorId)), fixture.windowsAlertIds());
        // by detector type, in the lowercased, the stored and another case
        for (String detectorType : List.of(WINDOWS_LOG_TYPE, mixedCaseLogType, WINDOWS_LOG_TYPE.toUpperCase(Locale.ROOT))) {
            assertAlerts(fixture, getAlertsApi(client(), params("detectorType", detectorType)), fixture.windowsAlertIds());
            Map<String, Object> page = getAlertsApi(client(), params("detectorType", detectorType, "sortString", "severity", "size", "1"));
            assertEquals(2, page.get("total_alerts"));
            assertEquals(1, alertIdsOf(page).size());
            assertTrue(fixture.windowsAlertIds().containsAll(alertIdsOf(page)));
        }
        assertAlerts(fixture, getAlertsApi(client(), params("detectorType", NETWORK_LOG_TYPE.toUpperCase(Locale.ROOT))), fixture.networkAlertIds());
        // without detector, with the alerts of the other log type, in every sort order
        assertAlerts(fixture, getAlertsApi(client(), Map.of()), allIds);
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            assertAlerts(fixture, getAlertsApi(client(), params("sortString", sortString, "sortOrder", "desc")), allIds);
        }
        assertEquals(alertIdsOf(getAlertsApi(client(), params("sortString", "state", "size", "4"))),
                fetchAllPages(client(), params("sortString", "state"), 1, 4));

        // a second detector of the same log type, stored lowercased, is grouped with the mixed-case one
        String lowercaseDetectorId = createDisabledDetector(client(), "windetectorlower", WINDOWS_LOG_TYPE, WINDOWS_INDEX,
                getRandomPrePackagedRules(), List.of(trigger("wintrigtwo", "2", WINDOWS_LOG_TYPE)));
        String lowercaseMonitorId = getDetectorMonitorIds(lowercaseDetectorId).get(0);
        // the new doc level monitor only reads documents indexed after its creation
        indexDoc(WINDOWS_INDEX, "3", randomDoc());
        indexDoc(WINDOWS_INDEX, "4", randomDoc());
        assertEquals(2, executeMonitorAndCountAlerts(lowercaseMonitorId));
        Set<String> lowercaseIds = waitForAlertDocs(List.of(WINDOWS_LOG_TYPE), List.of(lowercaseMonitorId), 2).stream()
                .map(alertDoc -> (String) alertDoc.get("_id")).collect(Collectors.toSet());
        for (String detectorType : List.of(WINDOWS_LOG_TYPE, mixedCaseLogType)) {
            Map<String, Object> body = getAlertsApi(client(), params("detectorType", detectorType));
            assertEquals(union(fixture.windowsAlertIds(), lowercaseIds), Set.copyOf(alertIdsOf(body)));
            assertEquals(4, body.get("total_alerts"));
        }
        Map<String, Object> body = getAlertsApi(client(), Map.of());
        assertEquals(union(allIds, lowercaseIds), Set.copyOf(alertIdsOf(body)));
        assertEquals(6, body.get("total_alerts"));
    }

    /**
     * The alerts of all detectors, restricted to the alerts of a detector, are the alerts returned for the detector id
     * (which are searched by Alerting), for the same filters, search string and time range.
     */
    public void testGetAlertsWithoutDetector_sameAlertsAsDetectorId() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        acknowledgeAndCompleteAlerts(fixture);
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        List<Long> startTimes = allIds.stream().map(id -> startTime(fixture, id)).sorted().collect(Collectors.toList());
        String from = String.valueOf(startTimes.get(startTimes.size() / 2));
        String to = String.valueOf(startTimes.get(startTimes.size() - 1));

        List<Map<String, String>> requests = List.of(
                Map.of(),
                params("severityLevels", "1,2"),
                params("severityLevel", "3"),
                params("severityLevel", "4"),
                params("alertStates", "ACKNOWLEDGED"),
                params("alertStates", "ACTIVE,COMPLETED"),
                params("alertState", "COMPLETED"),
                params("alertState", "ACTIVE"),
                params("searchString", WINDOWS_DETECTOR_NAME),
                params("searchString", NETWORK_DETECTOR_NAME),
                params("searchString", "wintrigone"),
                params("searchString", "*trig*"),
                params("searchString", "_exists_:monitor_name AND nettrigfour"),
                params("startTime", from, "endTime", to),
                params("startTime", from, "endTime", to, "severityLevels", "1,4", "alertStates", "ACTIVE,ACKNOWLEDGED"),
                params("sortString", "severity", "sortOrder", "desc", "searchString", "windetector OR netdetector")
        );
        int nonEmpty = 0;
        for (Map<String, String> request : requests) {
            Map<String, String> withSize = new HashMap<>(request);
            withSize.put("size", "100");
            Map<String, Object> allDetectors = getAlertsApi(client(), withSize);
            List<String> allDetectorsIds = alertIdsOf(allDetectors);
            assertEquals(request.toString(), allDetectorsIds.size(), allDetectors.get("total_alerts"));
            Set<String> fromDetectorIds = new java.util.HashSet<>();
            for (String detectorId : List.of(fixture.windowsDetectorId, fixture.networkDetectorId)) {
                Map<String, String> detectorRequest = new HashMap<>(withSize);
                detectorRequest.put("detector_id", detectorId);
                Map<String, Object> detectorAlerts = getAlertsApi(client(), detectorRequest);
                List<String> detectorIds = alertIdsOf(detectorAlerts);
                Set<String> ofDetector = detectorId.equals(fixture.windowsDetectorId) ? fixture.windowsAlertIds() : fixture.networkAlertIds();
                assertEquals(request + " " + detectorId, Set.copyOf(detectorIds),
                        allDetectorsIds.stream().filter(ofDetector::contains).collect(Collectors.toSet()));
                assertEquals(detectorIds.size(), detectorAlerts.get("total_alerts"));
                fromDetectorIds.addAll(detectorIds);
            }
            assertEquals(request.toString(), fromDetectorIds, Set.copyOf(allDetectorsIds));
            if (allDetectorsIds.isEmpty() == false) {
                nonEmpty++;
            }
        }
        assertTrue(nonEmpty > requests.size() / 2);
    }

    /**
     * Pages are stable when alerts tie on the sort field and on the start time: the concatenated pages are the full
     * result, without duplicates or gaps, for every sort field and order.
     */
    @SuppressWarnings("unchecked")
    public void testGetAlertsWithoutDetector_pagesAreStableWhenAlertsTie() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        // every alert gets the same severity and start time; they are all ACTIVE
        long startTime = System.currentTimeMillis() - 60000;
        Request updateByQuery = new Request("POST", DetectorMonitorConfig.getAllAlertsIndicesPattern(WINDOWS_LOG_TYPE) + ","
                + DetectorMonitorConfig.getAllAlertsIndicesPattern(NETWORK_LOG_TYPE) + "/_update_by_query");
        updateByQuery.addParameter("refresh", "true");
        updateByQuery.addParameter("conflicts", "proceed");
        updateByQuery.setJsonEntity("{ \"query\": { \"match_all\": {} }, \"script\": { \"lang\": \"painless\", \"source\": "
                + "\"ctx._source.severity = '1'; ctx._source.start_time = params.start_time\", \"params\": { \"start_time\": " + startTime + " } } }");
        assertEquals(14, ((Number) entityAsMap(performAsAdmin(updateByQuery)).get("updated")).intValue());
        reloadAlertDocs(fixture);
        for (Map<String, Object> alertDoc : fixture.alertDocs.values()) {
            assertEquals("1", alertDoc.get("severity"));
            assertEquals("ACTIVE", alertDoc.get("state"));
            assertEquals(startTime, ((Number) alertDoc.get("start_time")).longValue());
        }

        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            for (String sortOrder : List.of("asc", "desc")) {
                Map<String, String> sortParams = params("sortString", sortString, "sortOrder", sortOrder);
                Map<String, String> fullParams = new HashMap<>(sortParams);
                fullParams.put("size", "100");
                Map<String, Object> full = getAlertsApi(client(), fullParams);
                assertAlerts(fixture, full, allIds);
                List<String> fullIds = alertIdsOf(full);
                assertEquals(sortString + " " + sortOrder, expectedSortValues(fixture, allIds, sortString, sortOrder),
                        sortValues(fixture, fullIds, sortString, sortOrder));
                // the same request returns the same order
                assertEquals(fullIds, alertIdsOf(getAlertsApi(client(), fullParams)));
                for (int pageSize : List.of(1, 3, 5)) {
                    List<String> pages = fetchAllPages(client(), sortParams, pageSize, 14);
                    assertEquals(sortString + " " + sortOrder + " pages of " + pageSize, fullIds, pages);
                }
                // the filters do not change the relative order of the alerts
                Map<String, String> filtered = new HashMap<>(fullParams);
                filtered.put("severityLevels", "1,2");
                filtered.put("alertStates", "ACTIVE,ACKNOWLEDGED");
                assertEquals(fullIds, alertIdsOf(getAlertsApi(client(), filtered)));
            }
        }
    }

    /**
     * The total is the exact number of matching alerts up to 10,000 (the max result window: pages beyond it cannot be
     * fetched). Pages up to the max result window can be fetched, pages beyond it are a client error.
     */
    public void testGetAlertsWithoutDetector_totalIsExactUpToMaxResultWindow() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        String windowsAlertId = sorted(fixture.windowsAlertIds()).get(0);
        Map<String, Object> template = new HashMap<>(fixture.alertDocs.get(windowsAlertId));
        String index = (String) template.remove("_index");
        template.remove("_id");
        // 10,000 more alerts of the windows detector's monitor, half of severity 5: 10,014 alerts
        int copies = 10000;
        StringBuilder bulk = new StringBuilder();
        for (int i = 0; i < copies; i++) {
            Map<String, Object> copy = new HashMap<>(template);
            copy.put("severity", i % 2 == 0 ? "5" : "1");
            copy.put("start_time", ((Number) template.get("start_time")).longValue() - i - 1);
            bulk.append("{ \"index\": { \"_index\": \"").append(index).append("\", \"_id\": \"bulk_alert_").append(i)
                    .append("\", \"routing\": \"").append(fixture.windowsMonitorId).append("\" } }\n");
            bulk.append(org.opensearch.common.xcontent.XContentFactory.jsonBuilder().map(copy).toString()).append('\n');
        }
        Request bulkRequest = new Request("POST", "_bulk");
        bulkRequest.addParameter("refresh", "true");
        bulkRequest.setJsonEntity(bulk.toString());
        assertEquals(Boolean.FALSE, entityAsMap(performAsAdmin(bulkRequest)).get("errors"));

        assertEquals(10000, getAlertsApi(client(), params("size", "0")).get("total_alerts"));
        assertEquals(10000, getAlertsApi(client(), params("sortString", "severity", "sortOrder", "desc")).get("total_alerts"));
        // below the max result window the total is exact: 5,000 alerts of severity 5, 5,000 + 4 of severity 1
        assertEquals(copies / 2, getAlertsApi(client(), params("severityLevel", "5", "size", "0")).get("total_alerts"));
        assertEquals(copies / 2 + 4, getAlertsApi(client(), params("severityLevels", "1", "size", "0")).get("total_alerts"));
        assertEquals(copies / 2 + 10, getAlertsApi(client(), params("severityLevels", "1,2,4", "size", "0")).get("total_alerts"));
        assertEquals(6, getAlertsApi(client(), params("searchString", NETWORK_DETECTOR_NAME, "size", "0")).get("total_alerts"));

        // the last page within the max result window
        Map<String, Object> lastPage = getAlertsApi(client(), params("startIndex", "9990", "size", "10", "sortString", "start_time"));
        assertEquals(10, alertIdsOf(lastPage).size());
        assertEquals(10000, lastPage.get("total_alerts"));
        ResponseException e = expectThrows(ResponseException.class,
                () -> getAlertsApi(client(), params("startIndex", "9991", "size", "10")));
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        assertTrue(responseBody(e), responseBody(e).contains("Result window is too large"));
    }

    /**
     * A detector without detector_type (whose alert indices are unknown) is skipped: the alerts of the other detectors
     * are returned.
     */
    @SuppressWarnings("unchecked")
    public void testGetAlertsWithoutDetector_skipsDetectorWithoutDetectorType() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        Map<String, Object> source = new HashMap<>(getDetectorSource(fixture.networkDetectorId));
        Map<String, Object> detectorBody = new HashMap<>((Map<String, Object>) source.get("detector"));
        assertNotNull(detectorBody.remove("detector_type"));
        source.put("detector", detectorBody);
        indexDocAsAdmin(org.opensearch.securityanalytics.model.Detector.DETECTORS_INDEX, fixture.networkDetectorId, null, source);
        assertNull(((Map<String, Object>) getDetectorSource(fixture.networkDetectorId).get("detector")).get("detector_type"));

        assertAlerts(fixture, getAlertsApi(client(), Map.of()), fixture.windowsAlertIds());
        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            assertAlerts(fixture, getAlertsApi(client(), params("sortString", sortString, "sortOrder", "desc")), fixture.windowsAlertIds());
        }
        assertAlerts(fixture, getAlertsApi(client(), params("detectorType", WINDOWS_LOG_TYPE)), fixture.windowsAlertIds());
    }

    /**
     * The tie-breakers of the sort of the alerts of all detectors (_index, monitor_id, _seq_no) do not cause deprecation
     * warnings, unlike sorting on _id, which loads the deprecated fielddata of _id.
     */
    public void testGetAlertsWithoutDetector_sortWithoutDeprecationWarnings() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        String indices = DetectorMonitorConfig.getAllAlertsIndicesPattern(WINDOWS_LOG_TYPE) + ","
                + DetectorMonitorConfig.getAllAlertsIndicesPattern(NETWORK_LOG_TYPE);
        Request idSort = new Request("GET", indices + "/_search");
        idSort.setJsonEntity("{ \"sort\": [ { \"state\": { \"unmapped_type\": \"keyword\" } }, { \"_id\": \"asc\" } ] }");
        // deprecation warnings are only emitted once per deprecation and X-Opaque-Id
        idSort.setOptions(RequestOptions.DEFAULT.toBuilder().addHeader("X-Opaque-Id", randomAlphaOfLength(20)));
        // sorting on _id is allowed, but deprecated
        org.opensearch.client.Response idSortResponse = performAsAdmin(idSort, idSort.getOptions().toBuilder());
        assertEquals(RestStatus.OK.getStatus(), idSortResponse.getStatusLine().getStatusCode());
        if (securityEnabled() == false) {
            // the deprecation warning is not returned in the response when the security plugin is enabled
            assertTrue(idSortResponse.getWarnings().toString(),
                    idSortResponse.getWarnings().stream().anyMatch(warning -> warning.contains("fielddata on the _id field is deprecated")));
        }

        Request tieBreakerSort = new Request("GET", indices + "/_search");
        tieBreakerSort.setOptions(RequestOptions.DEFAULT.toBuilder().addHeader("X-Opaque-Id", randomAlphaOfLength(20)));
        tieBreakerSort.setJsonEntity("{ \"sort\": [ { \"state\": { \"unmapped_type\": \"keyword\" } }, "
                + "{ \"start_time\": { \"order\": \"desc\", \"unmapped_type\": \"date\" } }, { \"_index\": \"asc\" }, "
                + "{ \"monitor_id\": { \"order\": \"asc\", \"unmapped_type\": \"keyword\" } }, { \"_seq_no\": \"asc\" } ] }");
        org.opensearch.client.Response tieBreakerResponse = performAsAdmin(tieBreakerSort, tieBreakerSort.getOptions().toBuilder());
        assertEquals(List.of(), tieBreakerResponse.getWarnings());

        for (String sortString : GetAlertsRequest.SORTABLE_FIELDS) {
            org.opensearch.client.Response response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI,
                    params("sortString", sortString), null);
            assertEquals(List.of(), response.getWarnings());
            assertEquals(14, asMap(response).get("total_alerts"));
        }
    }

    private void setDefaultAllowPartialSearchResults(Boolean allow) throws IOException {
        org.opensearch.client.Request request = new org.opensearch.client.Request("PUT", "_cluster/settings");
        request.setJsonEntity("{ \"persistent\": { \"search.default_allow_partial_results\": " + allow + " } }");
        client().performRequest(request);
    }

    private void assertBadRequest(Map<String, String> base, Map<String, String> invalid, String expectedMessage) {
        Map<String, String> request = new HashMap<>(base);
        request.putAll(invalid);
        ResponseException e = expectThrows(ResponseException.class, () -> getAlertsApi(client(), request));
        assertEquals(request.toString(), RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        String body = responseBody(e);
        assertTrue(request + " -> " + body, body.contains(expectedMessage));
    }

    private static String responseBody(ResponseException e) {
        try {
            return new String(e.getResponse().getEntity().getContent().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Creates the correlation alerts index and the threat intel alerts index with the plugin's mappings and an alert
     * each whose name, trigger, severity and state match the windows detector's alerts.
     */
    private void createCorrelationAndThreatIntelAlerts() throws IOException {
        long now = System.currentTimeMillis();
        // the plugin creates the correlation alerts index itself once findings get correlated
        if (indexExistsAsAdmin(CorrelationIndices.CORRELATION_ALERT_INDEX) == false) {
            createIndexAsAdmin(CorrelationIndices.CORRELATION_ALERT_INDEX, "{ \"settings\": { \"index.hidden\": true }, \"mappings\": "
                    + readResource("mappings/correlation_alert_mapping.json") + " }");
        }
        indexDocAsAdmin(CorrelationIndices.CORRELATION_ALERT_INDEX, "correlation_alert_id", null, Map.of(
                "correlated_finding_ids", List.of("finding"),
                "correlation_rule_id", "rule",
                "correlation_rule_name", WINDOWS_DETECTOR_NAME,
                "trigger_name", "wintrigone",
                "severity", "1",
                "state", "ACTIVE",
                "start_time", now,
                "schema_version", 1
        ));

        String threatIntelIndex = String.format(Locale.ROOT, "%s-history-%s-1", ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, "2026.01.01");
        assertFalse(indexExistsAsAdmin(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME));
        createIndexAsAdmin(threatIntelIndex, "{ \"settings\": { \"index.hidden\": true }, \"aliases\": { \""
                + ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME + "\": {} }, \"mappings\": "
                + readResource("mappings/threat_intel_alert_mapping.json") + " }");
        indexDocAsAdmin(threatIntelIndex, "threat_intel_alert_id", null, Map.of(
                "id", "threat_intel_alert_id",
                "monitor_id", "threat_intel_monitor_id",
                "monitor_name", WINDOWS_DETECTOR_NAME,
                "trigger_id", "trigger",
                "trigger_name", "wintrigone",
                "severity", "1",
                "state", "ACTIVE",
                "start_time", now,
                "ioc_value", "1.2.3.4",
                "ioc_type", "ipv4-addr"
        ));
        // searched as super admin: with security enabled, a regular user's search does not return system index docs
        assertEquals(1, executeSearchRequest(adminClient(), CorrelationIndices.CORRELATION_ALERT_INDEX,
                "{ \"query\": { \"match_all\": {} } }").getHits().getHits().length);
        assertEquals(1, executeSearchRequest(adminClient(), ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME,
                "{ \"query\": { \"match_all\": {} } }").getHits().getHits().length);
    }

    private static Set<String> withSeverity(AlertsFixture fixture, Set<String> ids, String... severities) {
        Set<String> severitySet = Set.of(severities);
        return ids.stream().filter(id -> severitySet.contains(fixture.alertDocs.get(id).get("severity"))).collect(Collectors.toSet());
    }

    private static long startTime(AlertsFixture fixture, String alertId) {
        return ((Number) fixture.alertDocs.get(alertId).get("start_time")).longValue();
    }
}
