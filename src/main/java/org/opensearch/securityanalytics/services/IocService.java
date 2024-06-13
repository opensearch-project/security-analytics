/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.action.FetchIocsActionResponse;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * IOC Service implements operations that interact with retrieving IOCs from data sources,
 * parsing them into threat intel data models (i.e., [IOC]), and ingesting them to system indexes.
 */
public class IocService {
    private final Logger log = LogManager.getLogger(IocService.class);

    public static final String IOC_INDEX_NAME_BASE = ".opensearch-sap-iocs";
    public static final String IOC_ALL_INDEX_PATTERN = IOC_INDEX_NAME_BASE + "-*";
    public static final String IOC_FEED_ID_PLACEHOLDER = "FEED_ID";
    public static final String IOC_INDEX_NAME_TEMPLATE = IOC_INDEX_NAME_BASE + "-" + IOC_FEED_ID_PLACEHOLDER;

    // TODO hurneyt implement history indexes + rollover logic
    public static final String IOC_HISTORY_WRITE_INDEX_ALIAS = IOC_INDEX_NAME_TEMPLATE + "-history-write";
    public static final String IOC_HISTORY_INDEX_PATTERN = "<." + IOC_INDEX_NAME_BASE + "-history-{now/d{yyyy.MM.dd.hh.mm.ss|UTC}}-1>";

    private Client client;
    private ClusterService clusterService;

    public IocService(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /**
     * Checks whether the [IOC_INDEX_NAME_BASE]-related index exists.
     * @param index The index to evaluate.
     * @return TRUE if the index is an IOC-related system index, and exists; else returns FALSE.
     */
    public boolean feedIndexExists(String index) {
        return index.startsWith(IOC_INDEX_NAME_BASE) && this.clusterService.state().routingTable().hasIndex(index);
    }

    public static String getFeedConfigIndexName(String feedSourceConfigId) {
        return IOC_INDEX_NAME_TEMPLATE.replace(IOC_FEED_ID_PLACEHOLDER, feedSourceConfigId.toLowerCase(Locale.ROOT));
    }

    // TODO hurneyt change ActionResponse to more specific response once it's available
    public String initFeedIndex(String feedSourceConfigId, ActionListener<FetchIocsActionResponse> listener) {
        String feedIndexName = getFeedConfigIndexName(feedSourceConfigId);
        if (!feedIndexExists(feedIndexName)) {
            var indexRequest = new CreateIndexRequest(feedIndexName)
                    .mapping(iocIndexMapping())
                    .settings(Settings.builder().put("index.hidden", true).build());
            ((AdminClient) client).indices().create(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse createIndexResponse) {
                    log.info("Created system index {}", feedIndexName);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to create system index {}", feedIndexName);
                    listener.onFailure(e);
                }
            });
        }
        return feedIndexName;
    }

    public void indexIocs(String feedSourceConfigId, List<IOC> iocs, ActionListener<FetchIocsActionResponse> listener) throws IOException {
        // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
        Integer batchSize = this.clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);

        String feedIndexName = initFeedIndex(feedSourceConfigId, listener);

        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        for (IOC ioc : iocs) {
            IndexRequest indexRequest = new IndexRequest(feedIndexName)
                    .opType(DocWriteRequest.OpType.INDEX)
                    .source(ioc.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
            }
        }
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        bulkRequestList.add(bulkRequest);

        GroupedActionListener<BulkResponse> bulkResponseListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
            int idx = 0;
            for (BulkResponse response : bulkResponses) {
                BulkRequest request = bulkRequestList.get(idx);
                if (response.hasFailures()) {
                    throw new OpenSearchException(
                            "Error occurred while ingesting IOCs to {} with an error {}",
                            StringUtils.join(request.getIndices()),
                            response.buildFailureMessage()
                    );
                }
            }
        }, listener::onFailure), bulkRequestList.size());

        for (BulkRequest req : bulkRequestList) {
            try {
                StashedThreadContext.run(client, () -> client.bulk(req, bulkResponseListener));
                listener.onResponse(new FetchIocsActionResponse(iocs));
            } catch (OpenSearchException e) {
                log.error("Failed to save IOCs.", e);
            }
        }
    }

    public String iocIndexMapping() {
        String iocMappingFile = "mappings/ioc_mapping.json";
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(iocMappingFile)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Failed to load ioc_mapping.json file [{}]", iocMappingFile), e);
            throw new IllegalStateException("Failed to load ioc_mapping.json file [" + iocMappingFile + "]", e);
        }
    }
}
