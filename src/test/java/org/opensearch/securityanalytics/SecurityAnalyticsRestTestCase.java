/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.util.IndexUtilsKt;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class SecurityAnalyticsRestTestCase extends OpenSearchRestTestCase {

    protected String createTestIndex(String index, String mapping) throws IOException {
        createTestIndex(index, mapping, Settings.EMPTY);
        return index;
    }

    protected String createTestIndex(String index, String mapping, Settings settings) throws IOException {
        createIndex(index, settings, mapping);
        return index;
    }

    protected Response makeRequest(RestClient client, String method, String endpoint, Map<String, String> params,
                                   HttpEntity entity, Header... headers) throws IOException {
        Request request = new Request(method, endpoint);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);

        for (Header header: headers) {
            options.addHeader(header.getName(), header.getValue());
        }
        request.setOptions(options.build());
        request.addParameters(params);
        if (entity != null) {
            request.setEntity(entity);
        }
        return client.performRequest(request);
    }

    protected Response executeAlertingMonitor(String monitorId, Map<String, String> params) throws IOException {
        return executeAlertingMonitor(client(), monitorId, params);
    }

    protected Response executeAlertingMonitor(RestClient client, String monitorId, Map<String, String> params) throws IOException {
        return makeRequest(client, "POST", String.format(Locale.getDefault(), "/_plugins/_alerting/monitors/%s/_execute", monitorId), params, null);
    }

    protected Response indexDoc(String index, String id, String doc) throws IOException {
        return indexDoc(client(), index, id, doc, true);
    }

    protected Response indexDoc(RestClient client, String index, String id, String doc, Boolean refresh) throws IOException {
        StringEntity requestBody = new StringEntity(doc, ContentType.APPLICATION_JSON);
        Map<String, String> params = refresh? Map.of("refresh", "true"): Collections.emptyMap();
        Response response = makeRequest(client, "PUT", String.format(Locale.getDefault(), "%s/_doc/%s", index, id), params, requestBody);

        Assert.assertTrue(String.format(Locale.getDefault(), "Unable to index doc: '%s...' to index: '%s'", doc.substring(0, 15), index), List.of(RestStatus.OK, RestStatus.CREATED).contains(restStatus(response)));
        return response;
    }

    protected HttpEntity toHttpEntity(Detector detector) throws IOException {
        return new StringEntity(toJsonString(detector), ContentType.APPLICATION_JSON);
    }

    protected RestStatus restStatus(Response response) {
        return RestStatus.fromCode(response.getStatusLine().getStatusCode());
    }

    protected Map<String, Object> asMap(Response response) throws IOException {
        return entityAsMap(response);
    }

    private String toJsonString(Detector detector) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(detector.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }
}