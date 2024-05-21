/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelFeedParser;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.model.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.feedMetadata.BuiltInTIFMetadataLoader;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TIFJobUpdateService {
    private static final Logger log = LogManager.getLogger(TIFJobUpdateService.class);

    private static final int SLEEP_TIME_IN_MILLIS = 5000; // 5 seconds
    private static final int MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS = 10 * 60 * 60 * 1000; // 10 hours
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final TIFJobParameterService jobSchedulerParameterService;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final BuiltInTIFMetadataLoader builtInTIFMetadataLoader;

    public TIFJobUpdateService(
            final ClusterService clusterService,
            final TIFJobParameterService jobSchedulerParameterService,
            final ThreatIntelFeedDataService threatIntelFeedDataService,
            BuiltInTIFMetadataLoader builtInTIFMetadataLoader) {
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.jobSchedulerParameterService = jobSchedulerParameterService;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.builtInTIFMetadataLoader = builtInTIFMetadataLoader;
    }

    // functions used in job Runner

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
            threatIntelFeedDataService.deleteThreatIntelDataIndex(indicesToDelete);
        } catch (Exception e) {
            log.error(
                    () -> new ParameterizedMessage("Failed to delete old threat intel feed index [{}]", indicesToDelete), e
            );
        }
        return indicesToDelete;
    }


    /**
     * Update threat intel feed data
     * <p>
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param jobSchedulerParameter the jobSchedulerParameter
     * @param renewLock             runnable to renew lock
     */
    public void createThreatIntelFeedData(final TIFJobParameter jobSchedulerParameter, final Runnable renewLock, final ActionListener<ThreatIntelIndicesResponse> listener) {
        Instant startTime = Instant.now();

        List<AbstractMap.SimpleEntry<TIFJobParameter, TIFMetadata>> tifMetadataList = new ArrayList<>();
        Map<String, TIFMetadata> indexTIFMetadataMap = new HashMap<>();
        for (TIFMetadata tifMetadata: builtInTIFMetadataLoader.getTifMetadataList()) {
            String indexName = jobSchedulerParameter.newIndexName(jobSchedulerParameter, tifMetadata);
            tifMetadataList.add(new AbstractMap.SimpleEntry<>(jobSchedulerParameter, tifMetadata));
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
                                    updateJobSchedulerParameterAsSucceeded(freshIndices, jobSchedulerParameter, startTime, endTime, listener);
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
                                                threatIntelFeedDataService.parseAndSaveThreatIntelFeedDataCSV(indexName, reader.iterator(), renewLock, tifMetadata, saveThreatIntelFeedResponseListener);
                                            } else {
                                                threatIntelFeedDataService.parseAndSaveThreatIntelFeedDataCSV(indexName, noHeaderReader.iterator(), renewLock, tifMetadata, saveThreatIntelFeedResponseListener);
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

        for (AbstractMap.SimpleEntry<TIFJobParameter, TIFMetadata> tifJobParameterTIFMetadataSimpleEntry : tifMetadataList) {
            setupIndex(tifJobParameterTIFMetadataSimpleEntry.getKey(), tifJobParameterTIFMetadataSimpleEntry.getValue(), createdThreatIntelIndices);
        }
    }

    // helper functions

    /***
     * Update jobSchedulerParameter as succeeded
     *
     * @param jobSchedulerParameter the jobSchedulerParameter
     */
    public void updateJobSchedulerParameterAsSucceeded(
            List<String> indices,
            final TIFJobParameter jobSchedulerParameter,
            final Instant startTime,
            final Instant endTime,
            final ActionListener<ThreatIntelIndicesResponse> listener
    ) {
        jobSchedulerParameter.setIndices(indices);
        jobSchedulerParameter.getUpdateStats().setLastSucceededAt(endTime);
        jobSchedulerParameter.getUpdateStats().setLastProcessingTimeInMillis(endTime.toEpochMilli() - startTime.toEpochMilli());
        jobSchedulerParameter.enable();
        jobSchedulerParameter.setState(TIFJobState.AVAILABLE);
        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter, listener);
        log.info(
                "threat intel feed data creation succeeded for {} and took {} seconds",
                jobSchedulerParameter.getName(),
                Duration.between(startTime, endTime)
        );
    }

    /***
     * Create index to add a new threat intel feed data
     *
     * @param jobSchedulerParameter the jobSchedulerParameter
     * @param tifMetadata
     * @return new index name
     */
    private void setupIndex(final TIFJobParameter jobSchedulerParameter, TIFMetadata tifMetadata, ActionListener<CreateIndexResponse> listener) {
        String indexName = jobSchedulerParameter.newIndexName(jobSchedulerParameter, tifMetadata);
        jobSchedulerParameter.getIndices().add(indexName);
        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter, new ActionListener<>() {
            @Override
            public void onResponse(ThreatIntelIndicesResponse response) {
                if (response.isAcknowledged()) {
                    threatIntelFeedDataService.createIndexIfNotExists(indexName, listener);
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
}
