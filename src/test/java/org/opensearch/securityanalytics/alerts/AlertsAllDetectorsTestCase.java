/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.util.CorrelationIndices;

import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomNetworkDoc;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

/**
 * Builds two detectors of different log types with alerts, for tests of the alerts API without detector id / type.
 */
public abstract class AlertsAllDetectorsTestCase extends SecurityAnalyticsRestTestCase {

    protected static final String WINDOWS_LOG_TYPE = randomDetectorType();
    protected static final String NETWORK_LOG_TYPE = "network";
    protected static final String WINDOWS_INDEX = "windows";
    protected static final String NETWORK_INDEX = "netflow_test";

    /** Detector and trigger names are single tokens so that they can be used as searchString */
    protected static final String WINDOWS_DETECTOR_NAME = "windetector";
    protected static final String NETWORK_DETECTOR_NAME = "netdetector";

    /** Two detectors of different log types with alerts, and the alert docs as stored in the alert indices. */
    protected static class AlertsFixture {
        String windowsDetectorId;
        String networkDetectorId;
        String windowsMonitorId;
        String networkMonitorId;
        /** alert id --> alert doc */
        final Map<String, Map<String, Object>> alertDocs = new HashMap<>();

        Set<String> alertIdsOf(String monitorId) {
            return alertDocs.entrySet().stream()
                    .filter(e -> monitorId.equals(e.getValue().get("monitor_id")))
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());
        }

        Set<String> windowsAlertIds() {
            return alertIdsOf(windowsMonitorId);
        }

        Set<String> networkAlertIds() {
            return alertIdsOf(networkMonitorId);
        }

        String detectorIdOf(String alertId) {
            return windowsMonitorId.equals(alertDocs.get(alertId).get("monitor_id")) ? windowsDetectorId : networkDetectorId;
        }
    }

    protected void createLogIndices() throws IOException {
        createTestIndex(WINDOWS_INDEX, windowsIndexMapping());
        createMappingsAPI(WINDOWS_INDEX, WINDOWS_LOG_TYPE);
        createTestIndex(NETWORK_INDEX, netFlowMappings());
        createMappingsAPI(NETWORK_INDEX, "netflow");
    }

    /** Windows detector with triggers of severity 1 and 3: every matching document creates two alerts. */
    protected String createWindowsDetector(RestClient client, String name) throws IOException {
        return createDisabledDetector(client, name, WINDOWS_LOG_TYPE, WINDOWS_INDEX, getRandomPrePackagedRules(), List.of(
                trigger("wintrigone", "1", WINDOWS_LOG_TYPE),
                trigger("wintrigthree", "3", WINDOWS_LOG_TYPE)));
    }

    /** Network detector with triggers of severity 2 and 4: every matching document creates two alerts. */
    protected String createNetworkDetector(RestClient client, String name) throws IOException {
        return createDisabledDetector(client, name, NETWORK_LOG_TYPE, NETWORK_INDEX, getPrePackagedRules(NETWORK_LOG_TYPE), List.of(
                trigger("nettrigtwo", "2", NETWORK_LOG_TYPE),
                trigger("nettrigfour", "4", NETWORK_LOG_TYPE)));
    }

    protected static DetectorTrigger trigger(String name, String severity, String logType) {
        return new DetectorTrigger(null, name, severity, List.of(logType), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    /**
     * Creates the windows detector (8 alerts) and the network detector (6 alerts). The monitors are executed
     * alternately so that the alerts of both detectors interleave when sorted by time.
     */
    protected AlertsFixture createAlertsFixture(RestClient windowsDetectorCreator, RestClient networkDetectorCreator) throws Exception {
        createLogIndices();
        AlertsFixture fixture = new AlertsFixture();
        fixture.windowsDetectorId = createWindowsDetector(windowsDetectorCreator, WINDOWS_DETECTOR_NAME);
        fixture.networkDetectorId = createNetworkDetector(networkDetectorCreator, NETWORK_DETECTOR_NAME);
        fixture.windowsMonitorId = getDetectorMonitorIds(fixture.windowsDetectorId).get(0);
        fixture.networkMonitorId = getDetectorMonitorIds(fixture.networkDetectorId).get(0);

        int windowsAlerts = 0;
        int networkAlerts = 0;
        indexDoc(WINDOWS_INDEX, "1", randomDoc());
        indexDoc(WINDOWS_INDEX, "2", randomDoc());
        windowsAlerts += executeMonitorAndCountAlerts(fixture.windowsMonitorId);
        indexDoc(NETWORK_INDEX, "1", randomNetworkDoc());
        networkAlerts += executeMonitorAndCountAlerts(fixture.networkMonitorId);
        indexDoc(WINDOWS_INDEX, "3", randomDoc());
        indexDoc(WINDOWS_INDEX, "4", randomDoc());
        windowsAlerts += executeMonitorAndCountAlerts(fixture.windowsMonitorId);
        indexDoc(NETWORK_INDEX, "2", randomNetworkDoc());
        indexDoc(NETWORK_INDEX, "3", randomNetworkDoc());
        networkAlerts += executeMonitorAndCountAlerts(fixture.networkMonitorId);
        assertEquals(8, windowsAlerts);
        assertEquals(6, networkAlerts);

        for (Map<String, Object> alertDoc : waitForAlertDocs(List.of(WINDOWS_LOG_TYPE, NETWORK_LOG_TYPE),
                List.of(fixture.windowsMonitorId, fixture.networkMonitorId), 14)) {
            fixture.alertDocs.put((String) alertDoc.get("_id"), alertDoc);
        }
        assertEquals(8, fixture.windowsAlertIds().size());
        assertEquals(6, fixture.networkAlertIds().size());
        return fixture;
    }

    /** Reloads the fixture's alert docs from the alert indices (active and history) of both log types. */
    protected void reloadAlertDocs(AlertsFixture fixture) throws IOException, InterruptedException {
        fixture.alertDocs.clear();
        for (Map<String, Object> alertDoc : waitForAlertDocs(List.of(WINDOWS_LOG_TYPE, NETWORK_LOG_TYPE),
                List.of(fixture.windowsMonitorId, fixture.networkMonitorId), 14)) {
            fixture.alertDocs.put((String) alertDoc.get("_id"), alertDoc);
        }
    }

    /**
     * Moves an alert, as Alerting does once an alert completes, from the log type's active alert index to an alert
     * history index (.opensearch-sap-&lt;log type&gt;-alerts-history-*): the alert is indexed into the history index as
     * COMPLETED with an end time and deleted from the active index. The history index Alerting created for the log
     * type is used. The fixture is not reloaded.
     *
     * @return the history index
     */
    @SuppressWarnings("unchecked")
    protected String moveAlertToHistory(AlertsFixture fixture, String alertId, String logType, long endTime) throws IOException {
        Map<String, Object> alertDoc = new HashMap<>(fixture.alertDocs.get(alertId));
        String activeIndex = (String) alertDoc.remove("_index");
        alertDoc.remove("_id");
        assertEquals(DetectorMonitorConfig.getAlertsIndex(logType), activeIndex);

        Request getHistoryIndices = new Request("GET", "_cat/indices/" + DetectorMonitorConfig.getAlertsHistoryIndex(logType) + "-*");
        getHistoryIndices.addParameter("format", "json");
        getHistoryIndices.addParameter("expand_wildcards", "all");
        getHistoryIndices.addParameter("h", "index");
        List<Map<String, Object>> historyIndices = (List<Map<String, Object>>) (List<?>) entityAsList(performAsAdmin(getHistoryIndices));
        // Alerting creates the history index of the log type with its alert mapping along with the active alert index
        assertFalse("no alert history index of " + logType, historyIndices.isEmpty());
        String historyIndex = historyIndices.stream().map(index -> (String) index.get("index")).sorted().findFirst().orElseThrow();
        String monitorId = (String) alertDoc.get("monitor_id");
        alertDoc.put("state", "COMPLETED");
        alertDoc.put("end_time", endTime);
        indexDocAsAdmin(historyIndex, alertId, monitorId, alertDoc);

        Request delete = new Request("DELETE", activeIndex + "/_doc/" + alertId);
        delete.addParameter("refresh", "true");
        delete.addParameter("routing", monitorId);
        performAsAdmin(delete);
        return historyIndex;
    }

    protected org.opensearch.client.Response performAsAdmin(Request request) throws IOException {
        return performAsAdmin(request, RequestOptions.DEFAULT.toBuilder());
    }

    /** Performs the request as super admin with the given options, accepting warnings. */
    protected org.opensearch.client.Response performAsAdmin(Request request, RequestOptions.Builder options) throws IOException {
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
        request.setOptions(options.build());
        return adminClient().performRequest(request);
    }

    /**
     * Sort value of an alert doc for the sort field and order, null when missing: the smallest value of multi-valued
     * fields in ascending and the largest in descending order, like OpenSearch.
     */
    @SuppressWarnings("unchecked")
    protected static Comparable<Object> sortValue(AlertsFixture fixture, String alertId, String sortString, String sortOrder) {
        Object value = fixture.alertDocs.get(alertId).get(sortString.replace(".keyword", ""));
        if (value instanceof List) {
            List<Comparable<Object>> values = ((List<Object>) value).stream()
                    .map(v -> (Comparable<Object>) v)
                    .sorted()
                    .collect(Collectors.toList());
            if (values.isEmpty()) {
                return null;
            }
            return "desc".equalsIgnoreCase(sortOrder) ? values.get(values.size() - 1) : values.get(0);
        }
        return (Comparable<Object>) (value instanceof Number ? (Object) ((Number) value).longValue() : value);
    }

    protected static List<Object> sortValues(AlertsFixture fixture, List<String> ids, String sortString, String sortOrder) {
        return ids.stream().map(id -> (Object) sortValue(fixture, id, sortString, sortOrder)).collect(Collectors.toList());
    }

    /** The sort values of the alerts in the expected order: ascending or descending, missing values last. */
    protected static List<Object> expectedSortValues(AlertsFixture fixture, Set<String> ids, String sortString, String sortOrder) {
        java.util.Comparator<Comparable<Object>> order = "desc".equalsIgnoreCase(sortOrder)
                ? java.util.Comparator.reverseOrder()
                : java.util.Comparator.naturalOrder();
        return ids.stream().map(id -> sortValue(fixture, id, sortString, sortOrder))
                .sorted(java.util.Comparator.nullsLast(order))
                .collect(Collectors.toList());
    }

    /** Asserts the response contains exactly the expected alerts, with the right detector ids, and the right total. */
    protected static void assertAlerts(AlertsFixture fixture, Map<String, Object> getAlertsBody, Set<String> expectedAlertIds) {
        List<String> ids = alertIdsOf(getAlertsBody);
        assertEquals("duplicate alerts in " + ids, ids.size(), Set.copyOf(ids).size());
        assertEquals(expectedAlertIds, Set.copyOf(ids));
        assertEquals(expectedAlertIds.size(), getAlertsBody.get("total_alerts"));
        for (Map<String, Object> alert : alertsOf(getAlertsBody)) {
            assertEquals(fixture.detectorIdOf((String) alert.get("id")), alert.get("detector_id"));
        }
    }

    protected static Map<String, String> params(String... keyValues) {
        Map<String, String> params = new HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            params.put(keyValues[i], keyValues[i + 1]);
        }
        return params;
    }

    protected static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> union = new java.util.HashSet<>(a);
        union.addAll(b);
        return union;
    }

    /** Fetches all pages of the given size and returns the concatenated alert ids, checking the total of every page. */
    protected List<String> fetchAllPages(RestClient client, Map<String, String> params, int pageSize, int expectedTotal) throws IOException {
        List<String> ids = new ArrayList<>();
        for (int startIndex = 0; startIndex <= expectedTotal; startIndex += pageSize) {
            Map<String, String> pageParams = new HashMap<>(params);
            pageParams.put("size", String.valueOf(pageSize));
            pageParams.put("startIndex", String.valueOf(startIndex));
            Map<String, Object> page = getAlertsApi(client, pageParams);
            assertEquals(expectedTotal, page.get("total_alerts"));
            List<String> pageIds = alertIdsOf(page);
            assertEquals("page starting at " + startIndex, Math.max(0, Math.min(pageSize, expectedTotal - startIndex)), pageIds.size());
            ids.addAll(pageIds);
        }
        return ids;
    }

    protected static List<String> sorted(Set<String> ids) {
        List<String> list = new ArrayList<>(ids);
        Collections.sort(list);
        return list;
    }

    protected void setDefaultAllowPartialSearchResults(Boolean allow) throws IOException {
        org.opensearch.client.Request request = new org.opensearch.client.Request("PUT", "_cluster/settings");
        request.setJsonEntity("{ \"persistent\": { \"search.default_allow_partial_results\": " + allow + " } }");
        client().performRequest(request);
    }

    protected static String responseBody(ResponseException e) {
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
    protected void createCorrelationAndThreatIntelAlerts() throws IOException {
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
}
