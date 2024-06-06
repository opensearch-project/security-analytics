package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInput;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.threatIntel.resthandler.monitor.RestSearchThreatIntelMonitorAction.SEARCH_THREAT_INTEL_MONITOR_PATH;

public class ThreatIntelMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(ThreatIntelMonitorRestApiIT.class);

    public void testCreateThreatIntelMonitor() throws IOException {
        String monitorName = "test_monitor_name";
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);

        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto();
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        final String createdId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, createdId);

        Response alertingMonitorResponse = getAlertingMonitor(client(), createdId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());

        String matchAllRequest = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);

    }

    private ThreatIntelMonitorDto randomIocScanMonitorDto() {
        return new ThreatIntelMonitorDto(
                Monitor.NO_ID,
                randomAlphaOfLength(10),
                List.of(new PerIocTypeScanInput("IP", Map.of("abc", List.of("abc")), Collections.emptyList())),
                new org.opensearch.commons.alerting.model.IntervalSchedule(1, ChronoUnit.MINUTES, Instant.now()),
                true,
                null
        );
    }
}

