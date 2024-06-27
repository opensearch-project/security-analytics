package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.resthandler.ThreatIntelMonitorRestApiIT.randomIocScanMonitorDto;
import static org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME;

public class ThreatIntelAlertIT extends SecurityAnalyticsRestTestCase {
    public void testStatusUpdateFromAcknowledgedToComplete() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        Response response = makeRequest(client(),
                "POST",
                SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI,
                Collections.emptyMap(),
                toHttpEntity(iocScanMonitor));
        Map<String, Object> responseBody = asMap(response);
        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);
        List<String> alertIds = indexThreatIntelAlerts(monitorId, Alert.State.ACKNOWLEDGED);
        Response updateStatusResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_STATUS_URI,
                Map.of("alert_ids", String.join(",", alertIds), "state", "COMPLETED"), null);
        Map<String, Object> updateStatusResponseMap = responseAsMap(updateStatusResponse);
        ArrayList<HashMap<String, Object>> updatedAlerts = (ArrayList<HashMap<String, Object>>) updateStatusResponseMap.get("updated_alerts");
        assertEquals(2, updatedAlerts.size());
        assertTrue(alertIds.contains(updatedAlerts.get(0).get("id").toString()));
        assertTrue(alertIds.contains(updatedAlerts.get(1).get("id").toString()));
        assertEquals(Alert.State.COMPLETED.toString(), updatedAlerts.get(0).get("state").toString());
        assertEquals(Alert.State.COMPLETED.toString(), updatedAlerts.get(1).get("state").toString());
    }

    public void testStatusUpdateFromActiveToAcknowledged() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        Response response = makeRequest(client(),
                "POST",
                SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI,
                Collections.emptyMap(),
                toHttpEntity(iocScanMonitor));
        Map<String, Object> responseBody = asMap(response);
        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);
        List<String> alertIds = indexThreatIntelAlerts(monitorId, Alert.State.ACTIVE);
        Response updateStatusResponseEntity = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_STATUS_URI,
                Map.of("alert_ids", String.join(",", alertIds), "state", "ACKNOWLEDGED"), null);
        Map<String, Object> updateResponseMap = responseAsMap(updateStatusResponseEntity);
        ArrayList<HashMap<String, Object>> updatedAlerts = (ArrayList<HashMap<String, Object>>) updateResponseMap.get("updated_alerts");
        assertEquals(2, updatedAlerts.size());
        assertTrue(alertIds.contains(updatedAlerts.get(0).get("id").toString()));
        assertTrue(alertIds.contains(updatedAlerts.get(1).get("id").toString()));
        assertEquals(Alert.State.ACKNOWLEDGED.toString(), updatedAlerts.get(0).get("state").toString());
        assertEquals(Alert.State.ACKNOWLEDGED.toString(), updatedAlerts.get(1).get("state").toString());
    }

    private List<String> indexThreatIntelAlerts(String monitorId, Alert.State state) throws IOException {
        List<String> ids = new ArrayList<>();
        int i = 2;
        while (i-- > 0) {
            ThreatIntelAlert alert = new ThreatIntelAlert(
                    randomAlphaOfLength(10),
                    1,
                    1,
                    null,
                    randomAlphaOfLength(10),
                    randomAlphaOfLength(10),
                    monitorId,
                    randomAlphaOfLength(10),
                    state,
                    Instant.now(),
                    null,
                    Instant.now(),
                    Instant.now(),
                    null,
                    "high",
                    randomAlphaOfLength(10),
                    "ip",
                    Collections.emptyList(),
                    List.of(randomAlphaOfLength(10))
            );
            ids.add(alert.getId());
            makeRequest(client(), "POST", THREAT_INTEL_ALERT_ALIAS_NAME + "/_doc/" + alert.getId() + "?refresh", Map.of(),
                    new StringEntity(toJsonString(alert), ContentType.APPLICATION_JSON));

        }
        return ids;
    }
}
