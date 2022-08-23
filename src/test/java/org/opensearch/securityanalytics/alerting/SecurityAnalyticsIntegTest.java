/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.json.JSONObject;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.util.function.Supplier;

public abstract class SecurityAnalyticsIntegTest extends OpenSearchIntegTestCase {

    static boolean LOG = true;

    public static <T> T noLog(final Supplier<T> supplier) {
        LOG = false;
        final T t = supplier.get();
        LOG = true;
        return t;
    }

    public Response GET(final String route) throws IOException {
        return this.sendRequest(RestRequest.Method.GET.name(), route, null);
    }

    public Response GET(final String route, String json) throws IOException {
        return this.sendRequest(RestRequest.Method.GET.name(), route, json);
    }

    public Response PUT(final String route, final String json) throws IOException {
        return this.sendRequest(RestRequest.Method.PUT.name(), route, json);
    }

    public Response POST(final String route, final String json) throws IOException {
        return this.sendRequest(RestRequest.Method.POST.name(), route, json);
    }

    public Response POST(final String route) throws IOException {
        return this.sendRequest(RestRequest.Method.POST.name(), route, null);
    }

    public Response DELETE(final String route) throws IOException {
        return this.sendRequest(RestRequest.Method.DELETE.name(), route, null);
    }

    public Response sendRequest(final String method, final String route, final String jsonEntity) throws IOException {
        final Request request = new Request(method, route);
        if (null != jsonEntity) request.setJsonEntity(jsonEntity);
        final Response response = getRestClient().performRequest(request);
        if (LOG) {
            this.logger.info("\n" + method + " " + route + (null == jsonEntity ? "" : "\n" + new JSONObject(jsonEntity).toString(4)) +
                    "\n\t===>\n[STATUS: " + response.getStatusLine().getStatusCode() + "]" +
                    (null == response.getEntity() ? "" :
                            "\n" + TestTools.prettyString(response.getEntity().getContent())));
        }
        return response;
    }

}