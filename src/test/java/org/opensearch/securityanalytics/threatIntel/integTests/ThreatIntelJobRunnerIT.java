/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.integTests;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.junit.Ignore;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;
import static org.opensearch.securityanalytics.TestHelpers.*;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL;
import static org.opensearch.securityanalytics.threatIntel.util.ThreatIntelFeedDataUtils.getTifdList;

public class ThreatIntelJobRunnerIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(ThreatIntelJobRunnerIT.class);

    @Ignore
    public void testCreateDetector_threatIntelEnabled_testJobRunner() throws IOException, InterruptedException {

        // update job runner to run every minute
        updateClusterSetting(TIF_UPDATE_INTERVAL.getKey(), "1m");

        // Create a detector
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
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

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                Collections.emptyList());
        Detector detector = randomDetectorWithInputsAndThreatIntel(List.of(input), true);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));


        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(2, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        String detectoraLstUpdateTime1 = detectorMap.get("last_update_time").toString();

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        assertEquals(iocs.size(), 3);

        // get job runner index and verify parameters exist
        List<TIFJobParameter> jobMetaDataList = getJobSchedulerParameter();
        assertEquals(1, jobMetaDataList.size());
        TIFJobParameter jobMetaData = jobMetaDataList.get(0);
        Instant firstUpdatedTime = jobMetaData.getLastUpdateTime();
        assertNotNull("Job runner parameter index does not have metadata set", jobMetaData.getLastUpdateTime());
        assertEquals(jobMetaData.isEnabled(), true);

        // get list of first updated time for threat intel feed data
        List<Instant> originalFeedTimestamp = getThreatIntelFeedsTime();

        //verify feed index exists and each feed_id exists
        List<String> feedId = getThreatIntelFeedIds();
        assertNotNull(feedId);

        // wait for job runner to run
        Thread.sleep(60000);
        waitUntil(() -> {
            try {
                return verifyJobRan(firstUpdatedTime);
            } catch (IOException e) {
                throw new RuntimeException("failed to verify that job ran");
            }
        }, 240, TimeUnit.SECONDS);

        // verify job's last update time is different
        List<TIFJobParameter> newJobMetaDataList = getJobSchedulerParameter();
        assertEquals(1, newJobMetaDataList.size());
        TIFJobParameter newJobMetaData = newJobMetaDataList.get(0);
        Instant lastUpdatedTime = newJobMetaData.getLastUpdateTime();
        assertNotEquals(firstUpdatedTime.toString(), lastUpdatedTime.toString());

        // verify new threat intel feed timestamp is different
        List<Instant> newFeedTimestamp = getThreatIntelFeedsTime();
        for (int i = 0; i < newFeedTimestamp.size(); i++) {
            assertNotEquals(newFeedTimestamp.get(i), originalFeedTimestamp.get(i));
        }

        // verify detectors updated with latest threat intel feed data
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        String detectoraLstUpdateTime2 = detectorMap.get("last_update_time").toString();
        assertFalse(detectoraLstUpdateTime2.equals(detectoraLstUpdateTime1));

    }

    protected boolean verifyJobRan(Instant firstUpdatedTime) throws IOException {
        // verify job's last update time is different
        List<TIFJobParameter> newJobMetaDataList = getJobSchedulerParameter();
        assertEquals(1, newJobMetaDataList.size());

        TIFJobParameter newJobMetaData = newJobMetaDataList.get(0);
        Instant newUpdatedTime = newJobMetaData.getLastUpdateTime();
        if (!firstUpdatedTime.toString().equals(newUpdatedTime.toString())) {
            return true;
        }
        return false;
    }

    private List<String> getThreatIntelFeedIds() throws IOException {
        String request = getMatchAllSearchRequestString();
        SearchResponse res = executeSearchAndGetResponse(".opensearch-sap-threat-intel*", request, false);
        return getTifdList(res, xContentRegistry()).stream().map(it -> it.getFeedId()).collect(Collectors.toList());
    }

    private List<Instant> getThreatIntelFeedsTime() throws IOException {
        String request = getMatchAllSearchRequestString();
        SearchResponse res = executeSearchAndGetResponse(".opensearch-sap-threat-intel*", request, false);
        return getTifdList(res, xContentRegistry()).stream().map(it -> it.getTimestamp()).collect(Collectors.toList());
    }

    private List<TIFJobParameter> getJobSchedulerParameter() throws IOException {
        String request = getMatchAllSearchRequestString();
        SearchResponse res = executeSearchAndGetResponse(JOB_INDEX_NAME + "*", request, false);
        return getTIFJobParameterList(res, xContentRegistry()).stream().collect(Collectors.toList());
    }

    public static List<TIFJobParameter> getTIFJobParameterList(SearchResponse searchResponse, NamedXContentRegistry xContentRegistry) {
        List<TIFJobParameter> list = new ArrayList<>();
        if (searchResponse.getHits().getHits().length != 0) {
            Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
                try {
                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                            xContentRegistry,
                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                    );
                    list.add(TIFJobParameter.parse(xcp, hit.getId(), hit.getVersion()));
                } catch (Exception e) {
                    log.error(() -> new ParameterizedMessage(
                                    "Failed to parse TIF Job Parameter metadata from hit {}", hit),
                            e
                    );
                }

            });
        }
        return list;
    }

    private static String getMatchAllSearchRequestString() {
        return "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
    }

    private static String getMatchNumSearchRequestString(int num) {
        return "{\n" +
                "\"size\"  : " + num + "," +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
    }
}

