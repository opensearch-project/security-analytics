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
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.util.CorrelationIndices;

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
        varyAlertFields(fixture);
        // their indices match .opensearch-sap-*-alerts* but do not map all sortable fields
        createCorrelationAndThreatIntelAlerts();
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        // Searching indices that do not map the sort field fails those shards. Disallow partial results so that such
        // shard failures fail the request instead of being silently ignored.
        setDefaultAllowPartialSearchResults(false);
        try {
            assertSortingAndPaging(fixture, allIds);
        } finally {
            setDefaultAllowPartialSearchResults(null);
        }
    }

    private void assertSortingAndPaging(AlertsFixture fixture, Set<String> allIds) throws IOException {
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

        // same sort and paging for a single log type, which is served by a single Alerting search
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
        for (String sortString : List.of("monitor_name", "trigger_name", "foo", "id", "version", "error_message", "alert_history.timestamp")) {
            assertBadRequest(Map.of(), params("sortString", sortString), "sortString [" + sortString + "] is not supported");
        }
        // validation happens before any detector is looked up, in every mode
        for (Map<String, String> base : List.of(Map.<String, String>of(), params("detectorType", WINDOWS_LOG_TYPE),
                params("detector_id", "nonexistent_detector_id"))) {
            assertBadRequest(base, params("sortOrder", "up"), "sortOrder [up] is not supported");
            assertBadRequest(base, params("alertStates", "ACTIVE,FOO"), "contains invalid values [FOO]");
            assertBadRequest(base, params("alertStates", "ALL"), "contains invalid values [ALL]");
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
    }

    /**
     * Alerts of a detector id or a detector type are sorted by Alerting in a single search: like before, they can be
     * sorted on any field of the alert mapping, also on fields alerts of all detectors cannot be sorted on.
     */
    public void testGetAlertsOfDetectorIdAndDetectorType_sortOnAnyAlertField() throws Exception {
        AlertsFixture fixture = createAlertsFixture(client(), client());
        varyAlertFields(fixture);
        List<Map<String, String>> modes = List.of(
                params("detector_id", fixture.windowsDetectorId),
                params("detectorType", WINDOWS_LOG_TYPE),
                params("detector_id", fixture.networkDetectorId),
                params("detectorType", NETWORK_LOG_TYPE));
        for (Map<String, String> mode : modes) {
            Set<String> expectedIds = mode.containsValue(fixture.windowsDetectorId) || mode.containsValue(WINDOWS_LOG_TYPE)
                    ? fixture.windowsAlertIds()
                    : fixture.networkAlertIds();
            for (String sortString : List.of("end_time", "acknowledged_time", "version", "id", "monitor_id", "schema_version")) {
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
        assertEquals(1, executeSearch(CorrelationIndices.CORRELATION_ALERT_INDEX, "{ \"query\": { \"match_all\": {} } }").size());
        assertEquals(1, executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, "{ \"query\": { \"match_all\": {} } }").size());
    }

    private static Set<String> withSeverity(AlertsFixture fixture, Set<String> ids, String... severities) {
        Set<String> severitySet = Set.of(severities);
        return ids.stream().filter(id -> severitySet.contains(fixture.alertDocs.get(id).get("severity"))).collect(Collectors.toSet());
    }

    private static long startTime(AlertsFixture fixture, String alertId) {
        return ((Number) fixture.alertDocs.get(alertId).get("start_time")).longValue();
    }
}
