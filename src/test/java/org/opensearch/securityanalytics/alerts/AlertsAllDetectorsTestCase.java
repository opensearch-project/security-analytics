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
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.opensearch.client.RestClient;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.DetectorTrigger;

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

    /**
     * Gives the fixture's alerts varied values in the alert fields the generated alerts leave missing or all equal
     * (end and acknowledged time, associated alert ids, clusters, workflow name, schema and monitor version), so that
     * sorting on them is meaningful. Some alerts keep missing values. The alert docs are updated as admin and the
     * fixture is refreshed.
     */
    protected void varyAlertFields(AlertsFixture fixture) throws IOException, InterruptedException {
        List<String> ids = sorted(fixture.alertDocs.keySet());
        for (int i = 0; i < ids.size(); i++) {
            Map<String, Object> alertDoc = fixture.alertDocs.get(ids.get(i));
            Map<String, Object> update = new HashMap<>();
            update.put("end_time", i % 3 == 0 ? null : 1_700_000_000_000L + randomIntBetween(0, 1000) * 1000L);
            update.put("acknowledged_time", i % 4 == 0 ? null : 1_700_000_000_000L + randomIntBetween(0, 1000) * 1000L);
            update.put("associated_alert_ids", randomSubsetOf(List.of("assoc1", "assoc2", "Assoc3", "assoc4")));
            update.put("clusters", randomSubsetOf(List.of("cluster1", "Cluster2", "cluster3")));
            update.put("workflow_name", randomFrom("", "workflowA", "WorkflowB", "workflowc"));
            // numbers whose lexicographic order differs from their numeric order
            update.put("schema_version", randomFrom(2, 5, 10, 9));
            update.put("monitor_version", randomFrom(1L, 3L, 12L, 100L));
            updateDocAsAdmin((String) alertDoc.get("_index"), ids.get(i), (String) alertDoc.get("monitor_id"), update);
        }
        fixture.alertDocs.clear();
        for (Map<String, Object> alertDoc : waitForAlertDocs(List.of(WINDOWS_LOG_TYPE, NETWORK_LOG_TYPE),
                List.of(fixture.windowsMonitorId, fixture.networkMonitorId), 14)) {
            fixture.alertDocs.put((String) alertDoc.get("_id"), alertDoc);
        }
    }

    private void updateDocAsAdmin(String index, String id, String routing, Map<String, Object> partialDoc) throws IOException {
        org.opensearch.client.Request request = new org.opensearch.client.Request("POST", index + "/_update/" + id);
        request.addParameter("refresh", "true");
        request.addParameter("routing", routing);
        request.setJsonEntity(org.opensearch.common.xcontent.XContentFactory.jsonBuilder().startObject()
                .field("doc", partialDoc).endObject().toString());
        org.opensearch.client.RequestOptions.Builder options = org.opensearch.client.RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(org.opensearch.client.WarningsHandler.PERMISSIVE);
        request.setOptions(options.build());
        adminClient().performRequest(request);
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
}
