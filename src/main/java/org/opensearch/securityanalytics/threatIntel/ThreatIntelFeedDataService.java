/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel;

import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobAction;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobRequest;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

/**
 * Service to handle CRUD operations on Threat Intel Feed Data
 */
public class ThreatIntelFeedDataService {

    private static final Logger log = LogManager.getLogger(ThreatIntelFeedDataService.class);

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

    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final NamedXContentRegistry xContentRegistry;
    private final Client client;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    public ThreatIntelFeedDataService(
            ClusterService clusterService,
            Client client,
            IndexNameExpressionResolver indexNameExpressionResolver,
            NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

    public void getThreatIntelFeedData(
            ActionListener<List<ThreatIntelFeedData>> listener
    ) {
        String tifdIndex = getLatestIndexByCreationDate();
        if (tifdIndex == null) {
            createThreatIntelFeedData(listener);
        } else {
            fetchThreatIntelFeedDataFromIndex(tifdIndex, listener);
        }
    }

    private String getLatestIndexByCreationDate() {
        return IndexUtils.getNewIndexByCreationDate(
                this.clusterService.state(),
                this.indexNameExpressionResolver,
                THREAT_INTEL_DATA_INDEX_NAME_PREFIX + "*"
        );
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
    public void createIndexIfNotExists(final String indexName, final ActionListener<CreateIndexResponse> listener) {
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

    /**
     * Puts threat intel feed from CSVRecord iterator into a given index in bulk
     *
     * @param indexName Index name to save the threat intel feed
     * @param iterator  TIF data to insert
     * @param renewLock Runnable to renew lock
     */
    public void parseAndSaveThreatIntelFeedDataCSV(
            final String indexName,
            final Iterator<CSVRecord> iterator,
            final Runnable renewLock,
            final TIFMetadata tifMetadata,
            final ActionListener<ThreatIntelIndicesResponse> listener
    ) throws IOException {
        if (indexName == null || iterator == null || renewLock == null) {
            throw new IllegalArgumentException("Parameters cannot be null, failed to save threat intel feed data");
        }

        TimeValue timeout = clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT);
        Integer batchSize = clusterSettings.get(SecurityAnalyticsSettings.BATCH_SIZE);

        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        List<ThreatIntelFeedData> tifdList = new ArrayList<>();
        while (iterator.hasNext()) {
            CSVRecord record = iterator.next();
            String iocType = tifMetadata.getIocType();
            Integer colNum = tifMetadata.getIocCol();
            String iocValue = record.values()[colNum].split(" ")[0];
            if (iocType.equals("ip") && !isValidIp(iocValue)) {
                log.info("Invalid IP address, skipping this ioc record.");
                continue;
            }
            String feedId = tifMetadata.getFeedId();
            Instant timestamp = Instant.now();
            ThreatIntelFeedData threatIntelFeedData = new ThreatIntelFeedData(iocType, iocValue, feedId, timestamp);
            tifdList.add(threatIntelFeedData);
        }
        for (ThreatIntelFeedData tifd : tifdList) {
            XContentBuilder tifData = tifd.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
            IndexRequest indexRequest = new IndexRequest(indexName);
            indexRequest.source(tifData);
            indexRequest.opType(DocWriteRequest.OpType.INDEX);
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
                bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            }
        }
        bulkRequestList.add(bulkRequest);

        GroupedActionListener<BulkResponse> bulkResponseListener = new GroupedActionListener<>(new ActionListener<>() {
            @Override
            public void onResponse(Collection<BulkResponse> bulkResponses) {
                int idx = 0;
                for (BulkResponse response: bulkResponses) {
                    BulkRequest request = bulkRequestList.get(idx);
                    if (response.hasFailures()) {
                        throw new OpenSearchException(
                                "error occurred while ingesting threat intel feed data in {} with an error {}",
                                StringUtils.join(request.getIndices()),
                                response.buildFailureMessage()
                        );
                    }
                }
                listener.onResponse(new ThreatIntelIndicesResponse(true, List.of(indexName)));
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        }, bulkRequestList.size());

        for (int i = 0; i < bulkRequestList.size(); ++i) {
            saveTifds(bulkRequestList.get(i), timeout, bulkResponseListener);
        }
        renewLock.run();
    }

    public static boolean isValidIp(String ip) {
        String ipPattern = "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$";
        Pattern pattern = Pattern.compile(ipPattern);
        Matcher matcher = pattern.matcher(ip);
        return matcher.matches();
    }

    public void saveTifds(BulkRequest bulkRequest, TimeValue timeout, ActionListener<BulkResponse> listener) {
        try {
            StashedThreadContext.run(client, () -> client.bulk(bulkRequest, listener));
        } catch (OpenSearchException e) {
            log.error("failed to save threat intel feed data", e);
        }

    }

    public void deleteThreatIntelDataIndex(final List<String> indices) {
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

    private void createThreatIntelFeedData(ActionListener<List<ThreatIntelFeedData>> listener) {
        client.execute(
                PutTIFJobAction.INSTANCE,
                new PutTIFJobRequest("feed_updater", clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL)),
                new ActionListener<>() {
                    @Override
                    public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                        log.debug("Acknowledged threat intel feed updater job created");
                        String tifdIndex = getLatestIndexByCreationDate();
                        fetchThreatIntelFeedDataFromIndex(tifdIndex, listener);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.debug("Failed to create threat intel feed updater job", e);
                    }
                }
        );
    }

    private void fetchThreatIntelFeedDataFromIndex(String tifdIndex, ActionListener<List<ThreatIntelFeedData>> listener) {
        SearchRequest searchRequest = new SearchRequest(tifdIndex);
        searchRequest.source().size(9999); //TODO: convert to scroll
        String finalTifdIndex = tifdIndex;
        client.search(searchRequest, ActionListener.wrap(r -> listener.onResponse(ThreatIntelFeedDataUtils.getTifdList(r, xContentRegistry)), e -> {
            log.error(String.format(
                    "Failed to fetch threat intel feed data from system index %s", finalTifdIndex), e);
            listener.onFailure(e);
        }));
    }

    private String getIndexMapping() {
        try {
            try (InputStream is = TIFJobParameterService.class.getResourceAsStream("/mappings/threat_intel_feed_mapping.json")) {
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
