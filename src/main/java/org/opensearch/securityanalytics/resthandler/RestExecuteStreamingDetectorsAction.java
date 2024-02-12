/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkShardRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.client.Requests;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ExecuteStreamingDetectorsAction;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.POST;

public class RestExecuteStreamingDetectorsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(ExecuteStreamingDetectorsAction.class);

    private final boolean allowExplicitIndex;

    public RestExecuteStreamingDetectorsAction(Settings settings) {
        this.allowExplicitIndex = MULTI_ALLOW_EXPLICIT_INDEX.get(settings);
    }

    @Override
    public String getName() {
        return "run_detectors_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(POST, String.format(Locale.getDefault(),
                        "%s/streaming/execute",
                        SecurityAnalyticsPlugin.DETECTOR_BASE_URI))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        // The below is copied from https://github.com/opensearch-project/OpenSearch/blob/1f8b62fed81424576184dc9ef1ebe69f5156c904/server/src/main/java/org/opensearch/rest/action/document/RestBulkAction.java#L87
        BulkRequest bulkRequest = Requests.bulkRequest();
        String defaultIndex = request.param("index");
        String defaultRouting = request.param("routing");
        FetchSourceContext defaultFetchSourceContext = FetchSourceContext.parseFromRestRequest(request);
        String defaultPipeline = request.param("pipeline");
        String waitForActiveShards = request.param("wait_for_active_shards");
        if (waitForActiveShards != null) {
            bulkRequest.waitForActiveShards(ActiveShardCount.parseString(waitForActiveShards));
        }
        Boolean defaultRequireAlias = request.paramAsBoolean(DocWriteRequest.REQUIRE_ALIAS, null);
        bulkRequest.timeout(request.paramAsTime("timeout", BulkShardRequest.DEFAULT_TIMEOUT));
        bulkRequest.setRefreshPolicy(request.param("refresh"));
        bulkRequest.add(
                request.requiredContent(),
                defaultIndex,
                defaultRouting,
                defaultFetchSourceContext,
                defaultPipeline,
                defaultRequireAlias,
                allowExplicitIndex,
                request.getMediaType()
        );

        return channel -> client.execute(ExecuteStreamingDetectorsAction.INSTANCE, bulkRequest, new RestToXContentListener<>(channel));
    }
}
