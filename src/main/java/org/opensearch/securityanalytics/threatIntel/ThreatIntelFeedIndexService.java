/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadataService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

/**
 * Service to handle CRUD operations on threat intel feeds indices
 * TODO: Rename to TIFIndexService
 */
public class ThreatIntelFeedIndexService {
    private static final Logger log = LogManager.getLogger(ThreatIntelFeedIndexService.class);
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final TIFJobSchedulerMetadataService tifJobSchedulerMetadataService;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final Client client;
    public static final String SETTING_INDEX_REFRESH_INTERVAL = "index.refresh_interval";
    private static final Map<String, Object> INDEX_SETTING_TO_CREATE = Map.of(
            IndexMetadata.SETTING_NUMBER_OF_SHARDS,
            1,
            IndexMetadata.SETTING_NUMBER_OF_REPLICAS,
            0,
            SETTING_INDEX_REFRESH_INTERVAL,
            -1,
            IndexMetadata.SETTING_INDEX_HIDDEN,
            true
    );

    public ThreatIntelFeedIndexService(
            final ClusterService clusterService,
            final TIFJobSchedulerMetadataService tifJobSchedulerMetadataService,
            final ThreatIntelFeedDataService threatIntelFeedDataService,
            Client client) {
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.tifJobSchedulerMetadataService = tifJobSchedulerMetadataService;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.client = client;
    }

    /**
     * Delete old feed indices except the one which is being used
     */
    public void deleteAllTifdIndices(List<String> oldIndices, List<String> newIndices) {
        try {
            oldIndices.removeAll(newIndices);
            if (false == oldIndices.isEmpty()) {
                deleteIndices(oldIndices);
            }
        } catch (Exception e) {
            log.error(
                    () -> new ParameterizedMessage("Failed to delete old threat intel feed indices {}", StringUtils.join(oldIndices)), e
            );
        }
    }

    private List<String> deleteIndices(final List<String> indicesToDelete) {
        List<String> deletedIndices = new ArrayList<>(indicesToDelete.size());
        for (String index : indicesToDelete) {
            if (false == clusterService.state().metadata().hasIndex(index)) {
                deletedIndices.add(index);
            }
        }
        indicesToDelete.removeAll(deletedIndices);
        try {
            deleteThreatIntelDataIndex(indicesToDelete);
        } catch (Exception e) {
            log.error(
                    () -> new ParameterizedMessage("Failed to delete old threat intel feed index [{}]", indicesToDelete), e
            );
        }
        return indicesToDelete;
    }

    private void deleteThreatIntelDataIndex(final List<String> indices) {
        if (indices == null || indices.isEmpty()) {
            return;
        }

        Optional<String> invalidIndex = indices.stream()
                .filter(index -> index.startsWith(THREAT_INTEL_DATA_INDEX_NAME_PREFIX) == false)
                .findAny();
        if (invalidIndex.isPresent()) {
            throw new OpenSearchException(
                    "the index[{}] is not threat intel data index which should start with {}",
                    invalidIndex.get(),
                    THREAT_INTEL_DATA_INDEX_NAME_PREFIX
            );
        }

        StashedThreadContext.run(
                client,
                () -> client.admin()
                        .indices()
                        .prepareDelete(indices.toArray(new String[0]))
                        .setIndicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN)
                        .setTimeout(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT))
                        .execute(new ActionListener<>() {
                            @Override
                            public void onResponse(AcknowledgedResponse response) {
                                if (response.isAcknowledged() == false) {
                                    onFailure(new OpenSearchException("failed to delete data[{}]", String.join(",", indices)));
                                }
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("unknown exception:", e);
                            }
                        })
        );
    }

    /**
     * Update threat intel feed data
     * <p>
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param tifJobSchedulerMetadata the tifJobSchedulerMetadata
     * @param renewLock runnable to renew lock
     * @param listener the action listener
     */
    public void createThreatIntelFeed(final TIFJobSchedulerMetadata tifJobSchedulerMetadata, final Runnable renewLock, final ActionListener<ThreatIntelIndicesResponse> listener) {
        List<AbstractMap.SimpleEntry<TIFJobSchedulerMetadata, TIFMetadata>> tifMetadataList = new ArrayList<>();
        GroupedActionListener<CreateIndexResponse> createdThreatIntelIndices = threatIntelFeedDataService.getCreateIndexResponse(tifJobSchedulerMetadata, renewLock, listener, tifMetadataList);
        for (AbstractMap.SimpleEntry<TIFJobSchedulerMetadata, TIFMetadata> tifJobSchedulerMetadataTIFMetadataSimpleEntry : tifMetadataList) {
            setupIndex(tifJobSchedulerMetadataTIFMetadataSimpleEntry.getKey(), tifJobSchedulerMetadataTIFMetadataSimpleEntry.getValue(), createdThreatIntelIndices);
        }
    }

    /**
     * Create index to add a new threat intel feed data
     *
     * @param tifJobSchedulerMetadata the tifJobSchedulerMetadata
     * @param tifMetadata
     * @param listener the action listener
     * @return new index name
     */
    private void setupIndex(final TIFJobSchedulerMetadata tifJobSchedulerMetadata, TIFMetadata tifMetadata, ActionListener<CreateIndexResponse> listener) {
        String indexName = tifJobSchedulerMetadata.newIndexName(tifJobSchedulerMetadata, tifMetadata);
        tifJobSchedulerMetadata.getIndices().add(indexName);
        tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, new ActionListener<>() {
            @Override
            public void onResponse(ThreatIntelIndicesResponse response) {
                if (response.isAcknowledged()) {
                    createIndexIfNotExists(indexName, listener);
                } else {
                    onFailure(new OpenSearchStatusException("update of job scheduler parameter failed", RestStatus.INTERNAL_SERVER_ERROR));
                }
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    /**
     * Create an index for a threat intel feed
     * <p>
     * Index setting start with single shard, zero replica, no refresh interval, and hidden.
     * Once the threat intel feed is indexed, do refresh and force merge.
     * Then, change the index setting to expand replica to all nodes, and read only allow delete.
     *
     * @param indexName index name
     */
    private void createIndexIfNotExists(final String indexName, final ActionListener<CreateIndexResponse> listener) {
        if (clusterService.state().metadata().hasIndex(indexName) == true) {
            listener.onResponse(new CreateIndexResponse(true, true, indexName));
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName).settings(INDEX_SETTING_TO_CREATE)
                .mapping(getIndexMapping()).timeout(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));
        StashedThreadContext.run(
                client,
                () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(CreateIndexResponse response) {
                        if (response.isAcknowledged()) {
                            listener.onResponse(response);
                        } else {
                            onFailure(new OpenSearchStatusException("Threat intel feed index creation failed", RestStatus.INTERNAL_SERVER_ERROR));
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                })
        );
    }

    private String getIndexMapping() {
        try {
            try (InputStream is = TIFJobSchedulerMetadataService.class.getResourceAsStream("/mappings/threat_intel_feed_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception when getting the threat intel index mapping", e);
            throw new SecurityAnalyticsException("Runtime exception when getting the threat intel index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }
}
