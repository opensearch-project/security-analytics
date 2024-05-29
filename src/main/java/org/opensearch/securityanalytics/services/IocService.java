/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.action.FetchIocsActionResponse;
import org.opensearch.securityanalytics.model.IocDao;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.IOC_INDEX_NAME_BASE;

/**
 * IOC Service implements operations that interact with retrieving IOCs from data sources,
 * parsing them into threat intel data models (i.e., [IocDao]), and ingesting them to system indexes.
 */
public class IocService {
    private final Logger log = LogManager.getLogger(IocService.class);
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
    public boolean hasIocSystemIndex(String index) {
        return index.startsWith(IOC_INDEX_NAME_BASE) && this.clusterService.state().routingTable().hasIndex(index);
    }

    public void initSystemIndexes(String index, ActionListener<FetchIocsActionResponse> listener) {
        if (!hasIocSystemIndex(index)) {
            var indexRequest = new CreateIndexRequest(index)
                    // TODO hurneyt finalize mappings once IOC data model PR is merged
//                        .mapping(iocMappings())
                    .settings(Settings.builder().put("index.hidden", true).build());
            ((AdminClient) client).indices().create(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse createIndexResponse) {
                    // TODO should this be info, or debug level?
                    log.info("Created system index {}", index);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to create system index {}", index);
                    listener.onFailure(e);
                }
            });
        }
    }

    public void indexIocs(List<IocDao> allIocs, ActionListener<FetchIocsActionResponse> listener) throws IOException {
        // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
        Integer batchSize = this.clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);

        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        for (IocDao ioc : allIocs) {
            initSystemIndexes(ioc.getType().getSystemIndexName(), listener);

            IndexRequest indexRequest = new IndexRequest(ioc.getType().getSystemIndexName())
                    .opType(DocWriteRequest.OpType.INDEX)
                    .source(ioc.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            }
        }
        bulkRequestList.add(bulkRequest);

        GroupedActionListener<BulkResponse> bulkResponseListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
            int idx = 0;
            for (BulkResponse response : bulkResponses) {
                BulkRequest request = bulkRequestList.get(idx);
                if (response.hasFailures()) {
                    throw new OpenSearchException(
                            "Error occurred while ingesting IOCs in {} with an error {}",
                            StringUtils.join(request.getIndices()),
                            response.buildFailureMessage()
                    );
                }
            }
            listener.onResponse(new FetchIocsActionResponse(allIocs));
        }, listener::onFailure), bulkRequestList.size());

        for (BulkRequest req : bulkRequestList) {
            try {
                StashedThreadContext.run(client, () -> client.bulk(req, bulkResponseListener));
            } catch (OpenSearchException e) {
                log.error("Failed to save IOCs.", e);
            }
        }
    }

}
