/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel;

import org.apache.commons.csv.CSVParser;
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
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.feedMetadata.BuiltInTIFMetadataLoader;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadataService;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobSchedulerMetadata.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

/**
 * Service to handle CRUD operations on Threat Intel Feed Data
 */
public class ThreatIntelFeedDataService {
    private static final Logger log = LogManager.getLogger(ThreatIntelFeedDataService.class);
    private static final int SLEEP_TIME_IN_MILLIS = 5000; // 5 seconds
    private static final int MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS = 10 * 60 * 60 * 1000; // 10 hours
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final NamedXContentRegistry xContentRegistry;
    private final Client client;
    private final BuiltInTIFMetadataLoader builtInTIFMetadataLoader;
    private final TIFJobSchedulerMetadataService tifJobSchedulerMetadataService;


    public ThreatIntelFeedDataService(
            ClusterService clusterService,
            Client client,
            NamedXContentRegistry xContentRegistry,
            BuiltInTIFMetadataLoader builtInTIFMetadataLoader,
            TIFJobSchedulerMetadataService tifJobSchedulerMetadataService) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.builtInTIFMetadataLoader = builtInTIFMetadataLoader;
        this.tifJobSchedulerMetadataService = tifJobSchedulerMetadataService;
    }

    public void getThreatIntelFeedData(
            ActionListener<List<ThreatIntelFeedData>> listener,
            String tifdIndex
    ) {
        SearchRequest searchRequest = new SearchRequest(tifdIndex);
        searchRequest.source().size(9999); //TODO: convert to scroll
        client.search(searchRequest, ActionListener.wrap(r -> listener.onResponse(ThreatIntelFeedDataUtils.getTifdList(r, xContentRegistry)), e -> {
            log.error(String.format(
                    "Failed to fetch threat intel feed data from system index %s", tifdIndex), e);
            listener.onFailure(e);
        }));
    }

    public GroupedActionListener<CreateIndexResponse> getCreateIndexResponseGroupedActionListener(
            TIFJobSchedulerMetadata tifJobSchedulerMetadata,
            Runnable renewLock, ActionListener<ThreatIntelIndicesResponse> listener,
            List<AbstractMap.SimpleEntry<TIFJobSchedulerMetadata, TIFMetadata>> tifMetadataList
    ) {
        Instant startTime = Instant.now();
        Map<String, TIFMetadata> indexTIFMetadataMap = new HashMap<>();
        for (TIFMetadata tifMetadata: builtInTIFMetadataLoader.getTifMetadataList()) {
            String indexName = tifJobSchedulerMetadata.newIndexName(tifJobSchedulerMetadata, tifMetadata);
            tifMetadataList.add(new AbstractMap.SimpleEntry<>(tifJobSchedulerMetadata, tifMetadata));
            indexTIFMetadataMap.put(indexName, tifMetadata);
        }

        GroupedActionListener<CreateIndexResponse> createdThreatIntelIndices = new GroupedActionListener<>(
                new ActionListener<>() {
                    @Override
                    public void onResponse(Collection<CreateIndexResponse> responses) {
                        try {

                            int noOfUnprocessedResponses = 0;
                            for (CreateIndexResponse response: responses) {
                                String indexName = response.index();
                                TIFMetadata tifMetadata = indexTIFMetadataMap.get(indexName);
                                if (tifMetadata.getFeedType().equals("csv")) {
                                    ++noOfUnprocessedResponses;
                                }
                            }
                            GroupedActionListener<ThreatIntelIndicesResponse> saveThreatIntelFeedResponseListener = new GroupedActionListener<>(new ActionListener<>() {
                                @Override
                                public void onResponse(Collection<ThreatIntelIndicesResponse> responses) {
                                    List<String> freshIndices = new ArrayList<>();
                                    for (ThreatIntelIndicesResponse response: responses) {
                                        Boolean succeeded = false;
                                        if (response.isAcknowledged()) {
                                            String indexName = response.getIndices().get(0);
                                            waitUntilAllShardsStarted(indexName, MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS);
                                            freshIndices.add(indexName);
                                            succeeded = true;
                                        }

                                        if (!succeeded) {
                                            log.error("Exception: failed to parse correct feed type");
                                            onFailure(new OpenSearchException("Exception: failed to parse correct feed type"));
                                        }
                                    }

                                    Instant endTime = Instant.now();
                                    updateJobSchedulerMetadataAsSucceeded(freshIndices, tifJobSchedulerMetadata, startTime, endTime, listener);
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    listener.onFailure(e);
                                }
                            }, noOfUnprocessedResponses);

                            for (CreateIndexResponse response: responses) {
                                String indexName = response.index();
                                TIFMetadata tifMetadata = indexTIFMetadataMap.get(indexName);
                                switch (tifMetadata.getFeedType()) {
                                    case "csv":
                                        try (CSVParser reader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)) {
                                            CSVParser noHeaderReader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata);
                                            boolean notFound = true;

                                            while (notFound) {
                                                CSVRecord hasHeaderRecord = reader.iterator().next();

                                                //if we want to skip this line and keep iterating
                                                if ((hasHeaderRecord.values().length ==1 && "".equals(hasHeaderRecord.values()[0])) || hasHeaderRecord.get(0).charAt(0) == '#' || hasHeaderRecord.get(0).charAt(0) == ' '){
                                                    noHeaderReader.iterator().next();
                                                } else { // we found the first line that contains information
                                                    notFound = false;
                                                }
                                            }
                                            if (tifMetadata.hasHeader()){
                                                parseAndSaveThreatIntelFeedDataCSV(indexName, reader.iterator(), renewLock, tifMetadata, saveThreatIntelFeedResponseListener);
                                            } else {
                                                parseAndSaveThreatIntelFeedDataCSV(indexName, noHeaderReader.iterator(), renewLock, tifMetadata, saveThreatIntelFeedResponseListener);
                                            }
                                        }
                                        break;
                                    default:
                                        // if the feed type doesn't match any of the supporting feed types, throw an exception
                                }
                            }
                        } catch (IOException ex) {
                            onFailure(ex);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                },
                tifMetadataList.size()
        );
        return createdThreatIntelIndices;
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

    /**
     * We wait until all shards are ready to serve search requests before updating job scheduler parameter to
     * point to a new index so that there won't be latency degradation during threat intel feed data update
     *
     * @param indexName the indexName
     */
    protected void waitUntilAllShardsStarted(final String indexName, final int timeout) {
        Instant start = Instant.now();
        try {
            while (Instant.now().toEpochMilli() - start.toEpochMilli() < timeout) {
                if (clusterService.state().routingTable().allShards(indexName).stream().allMatch(shard -> shard.started())) {
                    return;
                }
                Thread.sleep(SLEEP_TIME_IN_MILLIS);
            }
            throw new OpenSearchException(
                    "index[{}] replication did not complete after {} millis",
                    MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS
            );
        } catch (InterruptedException e) {
            log.error("runtime exception", e);
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Update tifJobSchedulerMetadata as succeeded
     * @param tifJobSchedulerMetadata the tifJobSchedulerMetadata
     * @param startTime the start time
     * @param endTime the end time
     * @param listener the action listener
     */
    public void updateJobSchedulerMetadataAsSucceeded(
            List<String> indices,
            final TIFJobSchedulerMetadata tifJobSchedulerMetadata,
            final Instant startTime,
            final Instant endTime,
            final ActionListener<ThreatIntelIndicesResponse> listener
    ) {
        tifJobSchedulerMetadata.setIndices(indices);
        tifJobSchedulerMetadata.getUpdateStats().setLastSucceededAt(endTime);
        tifJobSchedulerMetadata.getUpdateStats().setLastProcessingTimeInMillis(endTime.toEpochMilli() - startTime.toEpochMilli());
        tifJobSchedulerMetadata.enable();
        tifJobSchedulerMetadata.setState(TIFJobState.AVAILABLE);
        tifJobSchedulerMetadataService.updateJobSchedulerMetadata(tifJobSchedulerMetadata, listener);
        log.info(
                "threat intel feed data creation succeeded for {} and took {} seconds",
                tifJobSchedulerMetadata.getName(),
                Duration.between(startTime, endTime)
        );
    }
}
