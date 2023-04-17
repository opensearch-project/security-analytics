/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.apache.http.HttpStatus;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.CorrelationRule;

public class EventsCorrelationRestApiIT extends SecurityAnalyticsRestTestCase {

    public void testCreatingACorrelationRule() throws IOException {
        Request indexCorrelationRuleRequest = new Request("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI);
        // both req params and req body are supported
        indexCorrelationRuleRequest.setJsonEntity(
        "{\n" +
                "  \"name\": \"my_rule_11\"," +
                "  \"correlate\": [\n" +
                "    {\n" +
                "      \"index\": \"vpc_flow\",\n" +
                "      \"query\": \"dstaddr:4.5.6.7 or dstaddr:4.5.6.6\",\n" +
                "      \"category\": \"network\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"index\": \"windows\",\n" +
                "      \"query\": \"winlog.event_data.SubjectDomainName:NTAUTHORI*\",\n" +
                "      \"category\": \"windows\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"index\": \"ad_logs\",\n" +
                "      \"query\": \"ResultType:50126\",\n" +
                "      \"category\": \"ad_ldap\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"index\": \"app_logs\",\n" +
                "      \"query\": \"endpoint:/customer_records.txt\",\n" +
                "      \"category\": \"others_application\"\n" +
                "    }\n" +
                "  ]\n" +
                "}"
        );

        Response response = client().performRequest(indexCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"correlate\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"correlate.index\": \"ad_logs\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
        List<SearchHit> hits = executeSearch(CorrelationRule.CORRELATION_RULE_INDEX, request);
        assertEquals(1, hits.size());
        assertTrue(hits.get(0).getSourceAsMap().get("name").equals("my_rule_11"));
    }

    public void testDeletingACorrelationRule() throws IOException {
        Request indexCorrelationRuleRequest = new Request("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI);
        // both req params and req body are supported
        indexCorrelationRuleRequest.setJsonEntity(
                "{\n" +
                        "  \"name\": \"my_rule_11\"," +
                        "  \"correlate\": [\n" +
                        "    {\n" +
                        "      \"index\": \"vpc_flow\",\n" +
                        "      \"query\": \"dstaddr:4.5.6.7 or dstaddr:4.5.6.6\",\n" +
                        "      \"category\": \"network\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"windows\",\n" +
                        "      \"query\": \"winlog.event_data.SubjectDomainName:NTAUTHORI*\",\n" +
                        "      \"category\": \"windows\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"ad_logs\",\n" +
                        "      \"query\": \"ResultType:50126\",\n" +
                        "      \"category\": \"ad_ldap\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"app_logs\",\n" +
                        "      \"query\": \"endpoint:/customer_records.txt\",\n" +
                        "      \"category\": \"others_application\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}"
        );

        Response response = client().performRequest(indexCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        String createdCorrelationRuleId = (String) responseAsMap(response).get("_id");

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"correlate\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"correlate.index\": \"ad_logs\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
        List<SearchHit> hits = executeSearch(CorrelationRule.CORRELATION_RULE_INDEX, request);
        assertEquals(1, hits.size());
        assertTrue(hits.get(0).getSourceAsMap().get("name").equals("my_rule_11"));

        // Delete Correlation Rule
        Request deleteCorrelationRuleRequest = new Request("DELETE", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + createdCorrelationRuleId);
        response = client().performRequest(deleteCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify that rule is deleted
        request = "{ \"query\": { \"match_all\": {} } }";
        hits = executeSearch(CorrelationRule.CORRELATION_RULE_INDEX, request);
        assertEquals(0, hits.size());
    }

    public void testSearchingCorrelationRules_success() throws IOException {
        Request indexCorrelationRuleRequest = new Request("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI);
        // both req params and req body are supported
        indexCorrelationRuleRequest.setJsonEntity(
                "{\n" +
                        "  \"name\": \"my_rule_11\"," +
                        "  \"correlate\": [\n" +
                        "    {\n" +
                        "      \"index\": \"vpc_flow\",\n" +
                        "      \"query\": \"dstaddr:4.5.6.7 or dstaddr:4.5.6.6\",\n" +
                        "      \"category\": \"network\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"windows\",\n" +
                        "      \"query\": \"winlog.event_data.SubjectDomainName:NTAUTHORI*\",\n" +
                        "      \"category\": \"windows\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"ad_logs\",\n" +
                        "      \"query\": \"ResultType:50126\",\n" +
                        "      \"category\": \"ad_ldap\"\n" +
                        "    },\n" +
                        "    {\n" +
                        "      \"index\": \"app_logs\",\n" +
                        "      \"query\": \"endpoint:/customer_records.txt\",\n" +
                        "      \"category\": \"others_application\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}"
        );

        // Create multiple correlation rules
        // #1
        Response response = client().performRequest(indexCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        // #2
        response = client().performRequest(indexCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        // #3
        response = client().performRequest(indexCorrelationRuleRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());

        String searchRequest = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"correlate\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"correlate.index\": \"ad_logs\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Request searchCorrelationRuleRequest = new Request("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search");
        searchCorrelationRuleRequest.setJsonEntity(searchRequest);
        response = client().performRequest(searchCorrelationRuleRequest);
        SearchResponse searchResponse = SearchResponse.fromXContent(createParser(JsonXContent.jsonXContent, response.getEntity().getContent()));
        List<SearchHit> hits = Arrays.asList(searchResponse.getHits().getHits());

        assertEquals(3, hits.size());
        assertTrue(hits.get(0).getSourceAsMap().get("name").equals("my_rule_11"));
    }

    public void testSearchingCorrelationRules_indexNotExists() throws IOException {

        String searchRequest = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"correlate\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"correlate.index\": \"ad_logs\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Request searchCorrelationRuleRequest = new Request("POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search");
        searchCorrelationRuleRequest.setJsonEntity(searchRequest);
        Response response = client().performRequest(searchCorrelationRuleRequest);
        SearchResponse searchResponse = SearchResponse.fromXContent(createParser(JsonXContent.jsonXContent, response.getEntity().getContent()));
        List<SearchHit> hits = Arrays.asList(searchResponse.getHits().getHits());

        assertEquals(0, hits.size());
    }
}
