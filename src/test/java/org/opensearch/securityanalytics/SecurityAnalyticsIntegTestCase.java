/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.opensearch.client.*;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.Map;

public class SecurityAnalyticsIntegTestCase extends OpenSearchRestTestCase {

    protected String createTestIndex(String index, String mapping) throws IOException {
        createIndex(index, Settings.EMPTY, mapping);
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
}