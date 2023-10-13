/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.integTests;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.TestHelpers.*;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE;
import static org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataUtils.getTifdList;

public class ThreatIntelJobRunnerIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(ThreatIntelJobRunnerIT.class);

    public void testCreateDetector_threatIntelEnabled_updateDetectorWithNewThreatIntel() throws IOException {

        // 1. create a detector
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

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        assertEquals(iocs.size(),3);

        // 2. delete a threat intel feed ioc index manually
        List<String> feedId = getThreatIntelFeedIds(1);
        for (String feedid: feedId) {
            String name = String.format(Locale.ROOT, "%s-%s%s", ".opensearch-sap-threatintel", feedid, "1");
            deleteIndex(name);
        }

//        // 3. update the start time to a day before so it runs now
//        StringEntity stringEntity = new StringEntity(
//                "{\"doc\":{\"last_update_time\":{\"schedule\":{\"interval\":{\"start_time\":" +
//                        "\"$startTimeMillis\"}}}}}",
//                ContentType.APPLICATION_JSON
//        );
//
//        Response updateJobRespose = makeRequest(client(), "POST", ".scheduler-sap-threatintel-job/_update/$id" , Collections.emptyMap(), stringEntity, null, null);
//        assertEquals("Updated job scheduler", RestStatus.CREATED, restStatus(updateJobRespose));

        // 4. validate new ioc is created
        List<String> newIocs = getThreatIntelFeedIocs(1);
        assertEquals(0, newIocs.size()); //TODO
    }

    private List<String> getThreatIntelFeedIocs(int num) throws IOException {
        String request = getMatchAllSearchRequestString(num);
        SearchResponse res = executeSearchAndGetResponse(".opensearch-sap-threatintel*", request, false);
        return getTifdList(res, xContentRegistry()).stream().map(it -> it.getIocValue()).collect(Collectors.toList());
    }

    private List<String> getThreatIntelFeedIds(int num) throws IOException {
        String request = getMatchAllSearchRequestString(num);
        SearchResponse res = executeSearchAndGetResponse(".opensearch-sap-threatintel*", request, false);
        return getTifdList(res, xContentRegistry()).stream().map(it -> it.getFeedId()).collect(Collectors.toList());
    }

//    private String getJobSchedulerDoc(int num) throws IOException {
//        String request = getMatchAllSearchRequestString(num);
//        SearchResponse res = executeSearchAndGetResponse(".scheduler-sap-threatintel-job*", request, false);
//    }

    private static String getMatchAllSearchRequestString(int num) {
        return "{\n" +
                "\"size\"  : " + num + "," +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
    }
}

