/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Checks, with the security plugin and system index protection on, that the plugin reads and writes its log type and
 * pre-packaged rule indices itself, that a user with read on every index cannot read them directly, and that the
 * correlation history, which is not registered, still needs the caller's index permission.
 */
public class SecureSystemIndicesRestApiIT extends SecurityAnalyticsRestTestCase {

    private static final String READ_ONLY_USER = "sap_system_index_reader";
    private static final String ALL_INDICES_USER = "sap_all_indices_reader";
    private static final String ALL_INDICES_ROLE = "sap_all_indices_read";
    private static final String CORRELATION_HISTORY_INDEX = ".opensearch-sap-correlation-history-system-index-it";

    private RestClient readOnlyClient;
    private RestClient allIndicesClient;

    @Before
    public void createUsers() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        createUserWithData(READ_ONLY_USER, READ_ONLY_USER, "security_analytics_read_access", new String[] {});
        createUserWithDataAndCustomRole(ALL_INDICES_USER, ALL_INDICES_USER, ALL_INDICES_ROLE, new String[] {},
                List.of(), List.of("indices:data/read/search*"), List.of("*"));
        HttpHost[] hosts = getClusterHosts().toArray(new HttpHost[0]);
        readOnlyClient = new SecureRestClientBuilder(hosts, isHttps(), READ_ONLY_USER, password).setSocketTimeout(60000).build();
        allIndicesClient = new SecureRestClientBuilder(hosts, isHttps(), ALL_INDICES_USER, password).setSocketTimeout(60000).build();
    }

    @After
    public void deleteUsers() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        if (readOnlyClient != null) {
            readOnlyClient.close();
        }
        if (allIndicesClient != null) {
            allIndicesClient.close();
        }
        deleteUser(READ_ONLY_USER);
        deleteUser(ALL_INDICES_USER);
        tryDeletingRole(ALL_INDICES_ROLE);
        if (indexExistsAsAdmin(CORRELATION_HISTORY_INDEX)) {
            makeRequest(systemIndexClient(), "DELETE", CORRELATION_HISTORY_INDEX, Collections.emptyMap(), null);
        }
    }

    public void testLogTypesAndRulesNeedOnlyTheActionPermissions() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        Response logTypes = makeRequest(readOnlyClient, "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/_search",
                Collections.emptyMap(), json("{\"query\": {\"match_all\": {}}}"));
        assertEquals(RestStatus.OK, restStatus(logTypes));
        assertTrue("built-in log types are listed", totalHits(logTypes) > 0);

        Response rules = makeRequest(readOnlyClient, "POST", SecurityAnalyticsPlugin.RULE_BASE_URI + "/_search",
                Map.of("pre_packaged", "true"), json("{\"query\": {\"match_all\": {}}}"));
        assertEquals(RestStatus.OK, restStatus(rules));
        assertTrue("pre-packaged rules are listed", totalHits(rules) > 0);
    }

    public void testTheLogTypeAndRuleIndicesAreNotReadableDirectly() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        // Loads the log types and the pre-packaged rules, so both indices exist and hold documents
        makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI + "/_search", Map.of("pre_packaged", "true"),
                json("{\"query\": {\"match_all\": {}}}"));
        assertTrue(indexExistsAsAdmin(LogTypeService.LOG_TYPE_INDEX));
        assertTrue(indexExistsAsAdmin(Rule.PRE_PACKAGED_RULES_INDEX));

        for (String index : List.of(LogTypeService.LOG_TYPE_INDEX, Rule.PRE_PACKAGED_RULES_INDEX)) {
            assertNoDirectRead(index);
        }
    }

    public void testListingCorrelationsStillNeedsReadOnTheHistoryIndex() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        // The correlation history is not a system index, so the list API keeps checking the caller on it.
        createIndexAsAdmin(CORRELATION_HISTORY_INDEX, "{}");
        long now = System.currentTimeMillis();
        makeRequest(systemIndexClient(), "POST", CORRELATION_HISTORY_INDEX + "/_doc", Map.of("refresh", "true"), json(
                "{\"finding1\": \"finding-a\", \"finding2\": \"finding-b\", \"logType\": \"network-windows\","
                        + " \"corrRules\": [\"rule-1\"], \"timestamp\": " + now + "}"));

        ResponseException e = expectThrows(ResponseException.class, () -> makeRequest(readOnlyClient, "GET",
                SecurityAnalyticsPlugin.LIST_CORRELATIONS_URI,
                Map.of("start_timestamp", Long.toString(now - 60000L), "end_timestamp", Long.toString(now + 60000L)), null));
        assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    public void testALogTypeQueryThatReadsOtherDocumentsIsRefused() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        String moreLikeThis = "{\"query\": {\"more_like_this\": {\"fields\": [\"name\"],"
                + " \"like\": [{\"_index\": \"" + Detector.DETECTORS_INDEX + "\", \"_id\": \"any\"}]}}}";
        ResponseException e = expectThrows(ResponseException.class, () -> makeRequest(readOnlyClient, "POST",
                SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/_search", Collections.emptyMap(), json(moreLikeThis)));
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    public void testALogTypeNameInsideARegisteredPatternIsRefused() throws IOException {
        if (!securityEnabled()) {
            return;
        }
        String logType = "{\"name\": \"threat-intel-custom\", \"description\": \"d\", \"category\": \"Other\","
                + " \"source\": \"Custom\", \"tags\": {}}";
        ResponseException e = expectThrows(ResponseException.class, () -> makeRequest(client(), "POST",
                SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), json(logType)));
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /** Asserts that a user with read on every index gets nothing from a direct search of a system index. */
    private void assertNoDirectRead(String index) throws IOException {
        try {
            Response response = makeRequest(allIndicesClient, "POST", index + "/_search", Collections.emptyMap(),
                    json("{\"query\": {\"match_all\": {}}}"));
            assertEquals(index, 0, totalHits(response));
        } catch (ResponseException e) {
            assertEquals(index, RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    private static StringEntity json(String body) {
        return new StringEntity(body, ContentType.APPLICATION_JSON);
    }

    @SuppressWarnings("unchecked")
    private long totalHits(Response response) throws IOException {
        Map<String, Object> hits = (Map<String, Object>) asMap(response).get("hits");
        return ((Number) ((Map<String, Object>) hits.get("total")).get("value")).longValue();
    }
}
