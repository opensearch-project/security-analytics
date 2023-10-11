/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedParser;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class TIFJobUpdateService {
    private static final Logger log = LogManager.getLogger(TIFJobUpdateService.class);

    private static final int SLEEP_TIME_IN_MILLIS = 5000; // 5 seconds
    private static final int MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS = 10 * 60 * 60 * 1000; // 10 hours
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final TIFJobParameterService jobSchedulerParameterService;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;

    public TIFJobUpdateService(
            final ClusterService clusterService,
            final TIFJobParameterService jobSchedulerParameterService,
            final ThreatIntelFeedDataService threatIntelFeedDataService
    ) {
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.jobSchedulerParameterService = jobSchedulerParameterService;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
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
     * @param renewLock runnable to renew lock
     * @throws IOException
     */
    public List<String> createThreatIntelFeedData(final TIFJobParameter jobSchedulerParameter, final Runnable renewLock) throws IOException {
        // parse YAML containing list of threat intel feeds.yml
        // for each feed (ex. Feodo)
        // parse feed specific YAML containing TIFMetadata

        // for every threat intel feed
        // create and store a new TIFMetadata object

        // use the TIFMetadata to switch case feed type
        // parse through file and save threat intel feed data

        TIFMetadata tifMetadata = new TIFMetadata("alientvault_reputation_generic",
                "https://reputation.alienvault.com/reputation.generic",
                "Alienvault IP Reputation Feed",
                "OTX",
                "Alienvault IP Reputation Database",
                "csv",
                List.of("ip"),
                1,
                false);
        List<TIFMetadata> tifMetadataList = new ArrayList<>(); //todo populate from config instead of example
        tifMetadataList.add(tifMetadata);
        List<String> freshIndices = new ArrayList<>();
        for (TIFMetadata metadata : tifMetadataList) {
            String indexName = setupIndex(jobSchedulerParameter, tifMetadata);
            String[] header;

            Boolean succeeded;

            switch (tifMetadata.getFeedType()) {
                case "csv":
                    try (CSVParser reader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)) {
                        // iterate until we find first line without '#' and without empty line
                        CSVRecord findHeader = reader.iterator().next();
                        while ((findHeader.values().length ==1 && "".equals(findHeader.values()[0])) || findHeader.get(0).charAt(0) == '#' || findHeader.get(0).charAt(0) == ' ') {
                            findHeader = reader.iterator().next();
                        }
                        CSVRecord headerLine = findHeader;
                        header = ThreatIntelFeedParser.validateHeader(headerLine).values();
                        threatIntelFeedDataService.parseAndSaveThreatIntelFeedDataCSV(indexName, header, reader.iterator(), renewLock, tifMetadata);
                        succeeded = true;
                    }
                    break;
                default:
                    // if the feed type doesn't match any of the supporting feed types, throw an exception
                    succeeded = false;
            }
            waitUntilAllShardsStarted(indexName, MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS);

            if (!succeeded) {
                log.error("Exception: failed to parse correct feed type");
                throw new OpenSearchException("Exception: failed to parse correct feed type");
            }
            freshIndices.add(indexName);
        }
        return freshIndices;
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
            final Instant endTime
    ) {
        jobSchedulerParameter.setIndices(indices);
        jobSchedulerParameter.getUpdateStats().setLastSucceededAt(endTime);
        jobSchedulerParameter.getUpdateStats().setLastProcessingTimeInMillis(endTime.toEpochMilli() - startTime.toEpochMilli());
        jobSchedulerParameter.enable();
        jobSchedulerParameter.setState(TIFJobState.AVAILABLE);
        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
        log.info(
                "threat intel feed database creation succeeded for {} and took {} seconds",
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
    private String setupIndex(final TIFJobParameter jobSchedulerParameter, TIFMetadata tifMetadata) {
        String indexName = jobSchedulerParameter.newIndexName(jobSchedulerParameter, tifMetadata);
        jobSchedulerParameter.getIndices().add(indexName);
        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
        threatIntelFeedDataService.createIndexIfNotExists(indexName);
        return indexName;
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
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }
}
