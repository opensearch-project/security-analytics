/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.opensearch.OpenSearchException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedParser;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.common.TIFState;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

public class TIFJobUpdateService {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

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
     * Delete all indices except the one which are being used
     *
     * @param jobSchedulerParameter
     */
    public void deleteUnusedIndices(final TIFJobParameter jobSchedulerParameter) {
        try {
            List<String> indicesToDelete = jobSchedulerParameter.getIndices()
                    .stream()
                    .filter(index -> index.equals(jobSchedulerParameter.currentIndexName()) == false)
                    .collect(Collectors.toList());

            List<String> deletedIndices = deleteIndices(indicesToDelete);

            if (deletedIndices.isEmpty() == false) {
                jobSchedulerParameter.getIndices().removeAll(deletedIndices);
                jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
            }
        } catch (Exception e) {
            log.error("Failed to delete old indices for {}", jobSchedulerParameter.getName(), e);
        }
    }

    /**
     * Update jobSchedulerParameter with given systemSchedule and task
     *
     * @param jobSchedulerParameter jobSchedulerParameter to update
     * @param systemSchedule new system schedule value
     * @param task new task value
     */
    public void updateJobSchedulerParameter(final TIFJobParameter jobSchedulerParameter, final IntervalSchedule systemSchedule, final TIFJobTask task) {
        boolean updated = false;
        if (jobSchedulerParameter.getSchedule().equals(systemSchedule) == false) {
            jobSchedulerParameter.setSchedule(systemSchedule);
            updated = true;
        }
        if (jobSchedulerParameter.getTask().equals(task) == false) {
            jobSchedulerParameter.setTask(task);
            updated = true;
        }
        if (updated) {
            jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
        }
    }

    private List<String> deleteIndices(final List<String> indicesToDelete) {
        List<String> deletedIndices = new ArrayList<>(indicesToDelete.size());
        for (String index : indicesToDelete) {
            if (clusterService.state().metadata().hasIndex(index) == false) {
                deletedIndices.add(index);
                continue;
            }
            try {
                threatIntelFeedDataService.deleteThreatIntelDataIndex(index);
                deletedIndices.add(index);
            } catch (Exception e) {
                log.error("Failed to delete an index [{}]", index, e);
            }
        }
        return deletedIndices;
    }


    /**
     * Update threat intel feed data
     *
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param jobSchedulerParameter the jobSchedulerParameter
     * @param renewLock runnable to renew lock
     *
     * @throws IOException
     */
    public void updateOrCreateThreatIntelFeedData(final TIFJobParameter jobSchedulerParameter, final Runnable renewLock) throws IOException {
        URL url = new URL(jobSchedulerParameter.getDatabase().getEndpoint());
        TIFMetadata tifMetadata = TIFMetadata.Builder.build(url);

        Instant startTime = Instant.now();
        String indexName = setupIndex(jobSchedulerParameter);
        String[] header;
        List<String> fieldsToStore;
        Boolean succeeded;

        //switch case based on what type of feed
        switch(tifMetadata.getFeedType()) {
            case "csv":
                try (CSVParser reader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)) {
                    // iterate until we find first line without '#'
                    CSVRecord findHeader = reader.iterator().next();
                    while (findHeader.get(0).charAt(0) == '#' || findHeader.get(0).charAt(0) == ' ') {
                        findHeader = reader.iterator().next();
                    }
                    CSVRecord headerLine = findHeader;
                    header = ThreatIntelFeedParser.validateHeader(headerLine).values();
                    fieldsToStore = Arrays.asList(header).subList(0, header.length);
                    if (jobSchedulerParameter.isCompatible(fieldsToStore) == false) {
                        log.error("Exception: new fields does not contain all old fields");
                        throw new OpenSearchException(
                                "new fields [{}] does not contain all old fields [{}]",
                                fieldsToStore.toString(),
                                jobSchedulerParameter.getDatabase().getFields().toString()
                        );
                    }
                    threatIntelFeedDataService.saveThreatIntelFeedDataCSV(indexName, header, reader.iterator(), renewLock, tifMetadata);
                }
            default:
                // if the feed type doesn't match any of the supporting feed types, throw an exception
                succeeded = false;
                fieldsToStore = null;
        }

        if (!succeeded) {
            log.error("Exception: failed to parse correct feed type");
            throw new OpenSearchException("Exception: failed to parse correct feed type");
        }

        waitUntilAllShardsStarted(indexName, MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS);
        Instant endTime = Instant.now();
        updateJobSchedulerParameterAsSucceeded(indexName, jobSchedulerParameter, tifMetadata, fieldsToStore, startTime, endTime);
    }

    // helper functions
    /***
     * Update jobSchedulerParameter as succeeded
     *
     * @param manifest the manifest
     * @param jobSchedulerParameter the jobSchedulerParameter
     */
    private void updateJobSchedulerParameterAsSucceeded(
            final String newIndexName,
            final TIFJobParameter jobSchedulerParameter,
            final TIFMetadata manifest,
            final List<String> fields,
            final Instant startTime,
            final Instant endTime
    ) {
        jobSchedulerParameter.setCurrentIndex(newIndexName);
        jobSchedulerParameter.setDatabase(manifest, fields);
        jobSchedulerParameter.getUpdateStats().setLastSucceededAt(endTime);
        jobSchedulerParameter.getUpdateStats().setLastProcessingTimeInMillis(endTime.toEpochMilli() - startTime.toEpochMilli());
        jobSchedulerParameter.enable();
        jobSchedulerParameter.setState(TIFState.AVAILABLE);
        jobSchedulerParameterService.updateJobSchedulerParameter(jobSchedulerParameter);
        log.info(
                "threat intel feed database creation succeeded for {} and took {} seconds",
                jobSchedulerParameter.getName(),
                Duration.between(startTime, endTime)
        );
    }

    /***
     * Setup index to add a new threat intel feed data
     *
     * @param jobSchedulerParameter the jobSchedulerParameter
     * @return new index name
     */
    private String setupIndex(final TIFJobParameter jobSchedulerParameter) {
        String indexName = jobSchedulerParameter.newIndexName(UUID.randomUUID().toString());
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







    /**
     * Determine if update is needed or not
     *
     * Update is needed when all following conditions are met
     * 1. updatedAt value in jobSchedulerParameter is equal or before updateAt value in tifMetadata
     * 2. SHA256 hash value in jobSchedulerParameter is different with SHA256 hash value in tifMetadata
     *
     * @param jobSchedulerParameter
     * @param tifMetadata
     * @return
     */
    private boolean shouldUpdate(final TIFJobParameter jobSchedulerParameter, final TIFMetadata tifMetadata) {
//        if (jobSchedulerParameter.getDatabase().getUpdatedAt() != null
//                && jobSchedulerParameter.getDatabase().getUpdatedAt().toEpochMilli() > tifMetadata.getUpdatedAt()) {
//            return false;
//        }

//        if (tifMetadata.getSha256Hash().equals(jobSchedulerParameter.getDatabase().getSha256Hash())) {
//            return false;
//        }
        return true;
    }

    /**
     * Return header fields of threat intel feed data with given url of a manifest file
     *
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param TIFMetadataUrl the url of a manifest file
     * @return header fields of threat intel feed
     */
    public List<String> getHeaderFields(String TIFMetadataUrl) throws IOException {
        URL url = new URL(TIFMetadataUrl);
        TIFMetadata tifMetadata = TIFMetadata.Builder.build(url);

        try (CSVParser reader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)) {
            String[] fields = reader.iterator().next().values();
            return Arrays.asList(fields).subList(1, fields.length);
        }
    }
}
