package org.opensearch.securityanalytics.resthandler;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelTriggerDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.threatIntel.resthandler.monitor.RestSearchThreatIntelMonitorAction.SEARCH_THREAT_INTEL_MONITOR_PATH;

public class ThreatIntelMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    private final Logger log = LogManager.getLogger(ThreatIntelMonitorRestApiIT.class);

    private List<STIX2IOCDto> testIocDtos = new ArrayList<>();

    public String indexSourceConfigsAndIocs(List<String> iocVals) throws IOException {
        testIocDtos = new ArrayList<>();
        for (int i1 = 0; i1 < iocVals.size(); i1++) {
            // create IOCs
            STIX2IOCDto stix2IOCDto = new STIX2IOCDto(
                    "id" + i1,
                    "random",
                    new IOCType(IOCType.IPV4_TYPE),
                    iocVals.get(i1),
                    "",
                    Instant.now(),
                    Instant.now(),
                    "",
                    emptyList(),
                    "spec",
                    "configId",
                    "",
                    1L
            );

            testIocDtos.add(stix2IOCDto);
        }
        return indexTifSourceConfig(testIocDtos);
    }

    public String indexSourceConfigsAndIocs(List<String> ipVals, List<String> hashVals, List<String> domainVals) throws IOException {
        testIocDtos = new ArrayList<>();
        for (int i1 = 0; i1 < ipVals.size(); i1++) {
            // create IOCs
            STIX2IOCDto stix2IOCDto = new STIX2IOCDto(
                    "id" + randomAlphaOfLength(3),
                    "random",
                    new IOCType(IOCType.IPV4_TYPE),
                    ipVals.get(i1),
                    "",
                    Instant.now(),
                    Instant.now(),
                    "",
                    emptyList(),
                    "spec",
                    "configId",
                    "",
                    1L
            );

            testIocDtos.add(stix2IOCDto);
        }
        for (int i1 = 0; i1 < hashVals.size(); i1++) {
            // create IOCs
            STIX2IOCDto stix2IOCDto = new STIX2IOCDto(
                    "id" + randomAlphaOfLength(3),
                    "random",
                    new IOCType(IOCType.HASHES_TYPE),
                    hashVals.get(i1),
                    "",
                    Instant.now(),
                    Instant.now(),
                    "",
                    emptyList(),
                    "spec",
                    "configId",
                    "",
                    1L
            );

            testIocDtos.add(stix2IOCDto);
        }
        for (int i1 = 0; i1 < domainVals.size(); i1++) {
            // create IOCs
            STIX2IOCDto stix2IOCDto = new STIX2IOCDto(
                    "id" + randomAlphaOfLength(3),
                    "random",
                    new IOCType(IOCType.DOMAIN_NAME_TYPE),
                    domainVals.get(i1),
                    "",
                    Instant.now(),
                    Instant.now(),
                    "",
                    emptyList(),
                    "spec",
                    "configId",
                    "",
                    1L
            );

            testIocDtos.add(stix2IOCDto);
        }
        return indexTifSourceConfig(testIocDtos);
    }

    private String indexTifSourceConfig(List<STIX2IOCDto> testIocDtos) throws IOException {
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                "configId",
                SATIFSourceConfig.NO_VERSION,
                "name1",
                "STIX2",
                SourceConfigType.IOC_UPLOAD,
                "description",
                null,
                Instant.now(),
                new IocUploadSource(null, testIocDtos),
                null,
                Instant.now(),
                null,
                TIFJobState.AVAILABLE,
                RefreshType.FULL,
                null,
                null,
                false,
                List.of(IOCType.IPV4_TYPE, IOCType.HASHES_TYPE, IOCType.DOMAIN_NAME_TYPE),
                true
        );

        Response makeResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(RestStatus.CREATED, restStatus(makeResponse));

        Assert.assertEquals(201, makeResponse.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(makeResponse);
        return responseBody.get("_id").toString();
    }

    public void testCreateThreatIntelMonitor_monitorAliases() throws IOException {
        updateClusterSetting(SecurityAnalyticsSettings.IOC_SCAN_MAX_TERMS_COUNT.getKey(), "1");
        Response iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(0, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
        List<String> vals = List.of("ip1", "ip2");
        String createdId = indexSourceConfigsAndIocs(vals);

        String index = "alias1";
        Map<String, Map<String, Boolean>> testAlias = createTestAlias(index, 1, true);
        String monitorName = "test_monitor_name";

        /**create monitor */
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            fail();
        } catch (Exception e) {
            /** creating a second threat intel monitor should fail*/
            assertTrue(e.getMessage().contains("already exists"));
        }

        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);
        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Assert.assertEquals(200, executeResponse.getStatusLine().getStatusCode());

        Response alertingMonitorResponse = getAlertingMonitor(client(), monitorId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        int i = 1;
        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        String matchAllRequest = getMatchAllRequest();
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);
        makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));

        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(2, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        //alerts
        List<SearchHit> searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(4, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        // Use ListIOCs API to confirm expected number of findings are returned
        String listIocsUri = String.format("?%s=%s", ListIOCsActionRequest.FEED_IDS_FIELD, createdId);
        Response listIocsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.LIST_IOCS_URI + listIocsUri, Collections.emptyMap(), null);
        Map<String, Object> listIocsResponseMap = responseAsMap(listIocsResponse);
        List<Map<String, Object>> iocsMap = (List<Map<String, Object>>) listIocsResponseMap.get("iocs");
        assertEquals(2, iocsMap.size());
        iocsMap.forEach((iocDetails) -> {
            String iocId = (String) iocDetails.get("id");
            int numFindings = (Integer) iocDetails.get("num_findings");
            assertTrue(testIocDtos.stream().anyMatch(ioc -> iocId.equals(ioc.getId())));
            assertEquals(2, numFindings);
        });

        // Use ListIOCs API with large size to ensure matchQuery related bug is not throwing too many bool clauses exception
        listIocsUri = String.format("?%s=%s", "size", 1000);
        listIocsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.LIST_IOCS_URI, Collections.emptyMap(), null);
        assertEquals(200, listIocsResponse.getStatusLine().getStatusCode());
        listIocsResponseMap = responseAsMap(listIocsResponse);
        iocsMap = (List<Map<String, Object>>) listIocsResponseMap.get("iocs");
        assertTrue(2 < iocsMap.size()); // number should be greater than custom source iocs because of default config

        //alerts via system index search
        searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        // alerts via API
        Map<String, String> params = new HashMap<>();
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(4, getAlertsBody.get("total_alerts"));


        ThreatIntelMonitorDto updateMonitorDto = new ThreatIntelMonitorDto(
                monitorId,
                iocScanMonitor.getName() + "update",
                iocScanMonitor.getPerIocTypeScanInputList(),
                new IntervalSchedule(5, ChronoUnit.MINUTES, Instant.now()),
                false,
                null,
                List.of(iocScanMonitor.getTriggers().get(0), iocScanMonitor.getTriggers().get(1))
        );
        //update monitor
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), toHttpEntity(updateMonitorDto));
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        responseBody = asMap(response);
        assertEquals(responseBody.get("id").toString(), monitorId);
        assertEquals(((HashMap<String, Object>) responseBody.get("monitor")).get("name").toString(), iocScanMonitor.getName() + "update");

        //delete
        Response delete = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), null);
        Assert.assertEquals(200, delete.getStatusLine().getStatusCode());

        searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        totalHits = (HashMap<String, Object>) hits.get("total");
        totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 0);
    }



    public void testCreateThreatIntelMonitor_configureMultipleIndicatorTypesInMonitor() throws IOException {
        updateClusterSetting(SecurityAnalyticsSettings.IOC_SCAN_MAX_TERMS_COUNT.getKey(), "1");
        Response iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(0, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
        List<String> ipVals = List.of("ip1", "ip2");
        List<String> hashVals = List.of("h1", "h2");
        List<String> domainVals = List.of("d1", "d2");
        String createdId = indexSourceConfigsAndIocs(ipVals, hashVals, domainVals);

        String ipIndex = "ipAlias";
        createTestAlias(ipIndex, 1, true);
        String hashIndex = "hashAlias";
        createTestAlias(hashIndex, 1, true);
        String domainIndex = "domainAlias";
        createTestAlias(domainIndex, 1, true);


        /**create monitor */
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDtoWithMultipleIndicatorTypesToScan(ipIndex, hashIndex, domainIndex);
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            fail();
        } catch (Exception e) {
            /** creating a second threat intel monitor should fail*/
            assertTrue(e.getMessage().contains("already exists"));
        }

        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);
        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Assert.assertEquals(200, executeResponse.getStatusLine().getStatusCode());

        Response alertingMonitorResponse = getAlertingMonitor(client(), monitorId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        int i = 1;
        for (String val : ipVals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(ipIndex, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }
        for (String val : hashVals) {
            String doc = String.format("{\"hash\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(hashIndex, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }
        for (String val : domainVals) {
            String doc = String.format("{\"domain\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(domainIndex, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        String matchAllRequest = getMatchAllRequest();
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);
        makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON, false));

        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(6, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        //alerts
        List<SearchHit> searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(6, searchHits.size());
    }

    public void testCreateThreatIntelMonitor() throws IOException {
        updateClusterSetting(SecurityAnalyticsSettings.IOC_SCAN_MAX_TERMS_COUNT.getKey(), "1");
        Response iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(0, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
        List<String> vals = List.of("ip1", "ip2");
        String createdId = indexSourceConfigsAndIocs(vals);
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        String monitorName = "test_monitor_name";


        /**create monitor */
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            fail();
        } catch (Exception e) {
            /** creating a second threat intel monitor should fail*/
            assertTrue(e.getMessage().contains("already exists"));
        }

        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);

        Response alertingMonitorResponse = getAlertingMonitor(client(), monitorId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        int i = 1;
        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
                indexDoc(index, "" + i++, String.format("{\"ip\":\"1.2.3.4\", \"ip1\":\"1.2.3.4\"}", val, val));
                indexDoc(index, "" + i++, String.format("{\"random\":\"%s\", \"random1\":\"%s\"}", val, val));
            } catch (IOException e) {
                fail();
            }
        }

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        String matchAllRequest = getMatchAllRequest();
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);
        makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));


        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(2, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        //alerts
        List<SearchHit> searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(4, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        // Use ListIOCs API to confirm expected number of findings are returned
        String listIocsUri = String.format("?%s=%s", ListIOCsActionRequest.FEED_IDS_FIELD, createdId);
        Response listIocsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.LIST_IOCS_URI + listIocsUri, Collections.emptyMap(), null);
        Map<String, Object> listIocsResponseMap = responseAsMap(listIocsResponse);
        List<Map<String, Object>> iocsMap = (List<Map<String, Object>>) listIocsResponseMap.get("iocs");
        assertEquals(2, iocsMap.size());
        iocsMap.forEach((iocDetails) -> {
            String iocId = (String) iocDetails.get("id");
            int numFindings = (Integer) iocDetails.get("num_findings");
            assertTrue(testIocDtos.stream().anyMatch(ioc -> iocId.equals(ioc.getId())));
            assertEquals(2, numFindings);
        });

        //alerts via system index search
        searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        // alerts via API
        Map<String, String> params = new HashMap<>();
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(4, getAlertsBody.get("total_alerts"));


        ThreatIntelMonitorDto updateMonitorDto = new ThreatIntelMonitorDto(
                monitorId,
                iocScanMonitor.getName() + "update",
                iocScanMonitor.getPerIocTypeScanInputList(),
                new IntervalSchedule(5, ChronoUnit.MINUTES, Instant.now()),
                false,
                null,
                List.of(iocScanMonitor.getTriggers().get(0), iocScanMonitor.getTriggers().get(1))
        );
        //update monitor
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), toHttpEntity(updateMonitorDto));
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        responseBody = asMap(response);
        assertEquals(responseBody.get("id").toString(), monitorId);
        assertEquals(((HashMap<String, Object>) responseBody.get("monitor")).get("name").toString(), iocScanMonitor.getName() + "update");

        //delete
        Response delete = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), null);
        Assert.assertEquals(200, delete.getStatusLine().getStatusCode());

        searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        totalHits = (HashMap<String, Object>) hits.get("total");
        totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 0);
    }

    public void testCreateThreatIntelMonitorWithExistingDetector() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Response iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(0, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
        List<String> vals = List.of("ip1", "ip2");
        String createdId = indexSourceConfigsAndIocs(vals);
        String monitorName = "test_monitor_name";


        /**create monitor */
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
        response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            fail();
        } catch (Exception e) {
            /** creating a second threat intel monitor should fail*/
            assertTrue(e.getMessage().contains("already exists"));
        }

        final String monitorId = responseBody.get("id").toString();
        Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);

        Response alertingMonitorResponse = getAlertingMonitor(client(), monitorId);
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        int i = 1;
        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        String matchAllRequest = getMatchAllRequest();
        Response searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        HashMap<String, Object> hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        HashMap<String, Object> totalHits = (HashMap<String, Object>) hits.get("total");
        Integer totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 1);
        makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));


        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(2, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        //alerts
        List<SearchHit> searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        for (String val : vals) {
            String doc = String.format("{\"ip\":\"%s\", \"ip1\":\"%s\"}", val, val);
            try {
                indexDoc(index, "" + i++, doc);
            } catch (IOException e) {
                fail();
            }
        }
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        iocFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                Map.of(), null);
        responseAsMap = responseAsMap(iocFindingsResponse);
        Assert.assertEquals(4, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());

        // Use ListIOCs API to confirm expected number of findings are returned
        String listIocsUri = String.format("?%s=%s", ListIOCsActionRequest.FEED_IDS_FIELD, createdId);
        Response listIocsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.LIST_IOCS_URI + listIocsUri, Collections.emptyMap(), null);
        Map<String, Object> listIocsResponseMap = responseAsMap(listIocsResponse);
        List<Map<String, Object>> iocsMap = (List<Map<String, Object>>) listIocsResponseMap.get("iocs");
        assertEquals(2, iocsMap.size());
        iocsMap.forEach((iocDetails) -> {
            String iocId = (String) iocDetails.get("id");
            int numFindings = (Integer) iocDetails.get("num_findings");
            assertTrue(testIocDtos.stream().anyMatch(ioc -> iocId.equals(ioc.getId())));
            assertEquals(2, numFindings);
        });

        //alerts via system index search
        searchHits = executeSearch(ThreatIntelAlertService.THREAT_INTEL_ALERT_ALIAS_NAME, matchAllRequest);
        Assert.assertEquals(4, searchHits.size());

        // alerts via API
        Map<String, String> params = new HashMap<>();
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(4, getAlertsBody.get("total_alerts"));


        ThreatIntelMonitorDto updateMonitorDto = new ThreatIntelMonitorDto(
                monitorId,
                iocScanMonitor.getName() + "update",
                iocScanMonitor.getPerIocTypeScanInputList(),
                new IntervalSchedule(5, ChronoUnit.MINUTES, Instant.now()),
                false,
                null,
                List.of(iocScanMonitor.getTriggers().get(0), iocScanMonitor.getTriggers().get(1))
        );
        //update monitor
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), toHttpEntity(updateMonitorDto));
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        responseBody = asMap(response);
        assertEquals(responseBody.get("id").toString(), monitorId);
        assertEquals(((HashMap<String, Object>) responseBody.get("monitor")).get("name").toString(), iocScanMonitor.getName() + "update");

        //delete
        Response delete = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI + "/" + monitorId, Collections.emptyMap(), null);
        Assert.assertEquals(200, delete.getStatusLine().getStatusCode());

        searchMonitorResponse = makeRequest(client(), "POST", SEARCH_THREAT_INTEL_MONITOR_PATH, Collections.emptyMap(), new StringEntity(matchAllRequest, ContentType.APPLICATION_JSON));
        Assert.assertEquals(200, alertingMonitorResponse.getStatusLine().getStatusCode());
        hits = (HashMap<String, Object>) asMap(searchMonitorResponse).get("hits");
        totalHits = (HashMap<String, Object>) hits.get("total");
        totalHitsVal = (Integer) totalHits.get("value");
        assertEquals(totalHitsVal.intValue(), 0);
    }

    public void testCreateThreatIntelMonitor_invalidMonitorJson() throws IOException {
        ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto("test-index");

        String monitorJson = iocScanMonitor.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString();
        final String invalidMonitorJson = monitorJson.replace("\"interval\":1", "\"interval\":100000000000000000000000000000000000000");

        ResponseException exception = Assert.assertThrows(ResponseException.class,
                () -> makeRequest(
                        client(),
                        "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI,
                        Collections.emptyMap(),
                        new StringEntity(invalidMonitorJson, ContentType.APPLICATION_JSON)
                )
        );
        Assert.assertTrue(exception.getMessage().contains("Failed to parse threat intel monitor: "));
        Assert.assertTrue(exception.getMessage().contains("\"status\":400"));
    }

    public static String getMatchAllRequest() {
        return "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
    }

    public static ThreatIntelMonitorDto randomIocScanMonitorDto(String index) {
        ThreatIntelTriggerDto t1 = new ThreatIntelTriggerDto(List.of(index, "randomIndex"), List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE), emptyList(), "match", null, "severity");
        ThreatIntelTriggerDto t2 = new ThreatIntelTriggerDto(List.of("randomIndex"), List.of(IOCType.DOMAIN_NAME_TYPE), emptyList(), "nomatch", null, "severity");
        ThreatIntelTriggerDto t3 = new ThreatIntelTriggerDto(emptyList(), List.of(IOCType.DOMAIN_NAME_TYPE), emptyList(), "domainmatchsonomatch", null, "severity");
        ThreatIntelTriggerDto t4 = new ThreatIntelTriggerDto(List.of(index), emptyList(), emptyList(), "indexmatch", null, "severity");

        return new ThreatIntelMonitorDto(
                Monitor.NO_ID,
                randomAlphaOfLength(10),
                List.of(new PerIocTypeScanInputDto(IOCType.IPV4_TYPE, Map.of(index, List.of("ip")))),
                new IntervalSchedule(1, ChronoUnit.MINUTES, Instant.now()),
                false,
                null,
                List.of(t1, t2, t3, t4));
    }

    public static ThreatIntelMonitorDto randomIocScanMonitorDtoWithMultipleIndicatorTypesToScan(String ipIndex, String hashIndex, String domainIndex) {
        ThreatIntelTriggerDto t1 = new ThreatIntelTriggerDto(List.of(ipIndex, "randomIndex"), List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE), emptyList(), "match", null, "severity");
        ThreatIntelTriggerDto t2 = new ThreatIntelTriggerDto(List.of("randomIndex"), List.of(IOCType.DOMAIN_NAME_TYPE), emptyList(), "nomatch", null, "severity");
        ThreatIntelTriggerDto t3 = new ThreatIntelTriggerDto(emptyList(), List.of(IOCType.DOMAIN_NAME_TYPE), emptyList(), "domainmatchsonomatch", null, "severity");
        ThreatIntelTriggerDto t4 = new ThreatIntelTriggerDto(List.of(ipIndex), emptyList(), emptyList(), "indexmatch", null, "severity");

        return new ThreatIntelMonitorDto(
                Monitor.NO_ID,
                randomAlphaOfLength(10),
                List.of(
                        new PerIocTypeScanInputDto(IOCType.IPV4_TYPE, Map.of(ipIndex, List.of("ip"))),
                        new PerIocTypeScanInputDto(IOCType.HASHES_TYPE, Map.of(hashIndex, List.of("hash"))),
                        new PerIocTypeScanInputDto(IOCType.DOMAIN_NAME_TYPE, Map.of(domainIndex, List.of("domain")))
                ),
                new IntervalSchedule(1, ChronoUnit.MINUTES, Instant.now()),
                false,
                null,
                List.of(t1, t2, t3, t4));
    }

    @Override
    protected boolean preserveIndicesUponCompletion() {
        return false;
    }
}

