/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.jobscheduler;

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
import org.opensearch.securityanalytics.threatintel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatintel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatintel.dao.ThreatIntelFeedDao;
import org.opensearch.securityanalytics.threatintel.common.DatasourceState;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

public class DatasourceUpdateService {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final int SLEEP_TIME_IN_MILLIS = 5000; // 5 seconds
    private static final int MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS = 10 * 60 * 60 * 1000; // 10 hours
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final DatasourceDao datasourceDao;
    private final ThreatIntelFeedDao threatIntelFeedDao;

    public DatasourceUpdateService(
            final ClusterService clusterService,
            final DatasourceDao datasourceDao,
            final ThreatIntelFeedDao threatIntelFeedDao
    ) {
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.datasourceDao = datasourceDao;
        this.threatIntelFeedDao = threatIntelFeedDao;
    }

    /**
     * Update threat intel feed data
     *
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param datasource the datasource
     * @param renewLock runnable to renew lock
     *
     * @throws IOException
     */
    public void updateOrCreateThreatIntelFeedData(final Datasource datasource, final Runnable renewLock) throws IOException {
        URL url = new URL(datasource.getEndpoint());
        DatasourceManifest manifest = DatasourceManifest.Builder.build(url);

        if (shouldUpdate(datasource, manifest) == false) {
            log.info("Skipping threat intel feed database update. Update is not required for {}", datasource.getName());
            datasource.getUpdateStats().setLastSkippedAt(Instant.now());
            datasourceDao.updateDatasource(datasource);
            return;
        }

        Instant startTime = Instant.now();
        String indexName = setupIndex(datasource);
        String[] header;
        List<String> fieldsToStore;
        try (CSVParser reader = threatIntelFeedDao.getDatabaseReader(manifest)) {
            CSVRecord headerLine = reader.iterator().next();
            header = validateHeader(headerLine).values();
            fieldsToStore = Arrays.asList(header).subList(1, header.length);
            if (datasource.isCompatible(fieldsToStore) == false) {
                log.error("Exception: new fields does not contain all old fields");
                throw new OpenSearchException(
                        "new fields [{}] does not contain all old fields [{}]",
                        fieldsToStore.toString(),
                        datasource.getDatabase().getFields().toString()
                );
            }
            threatIntelFeedDao.putTIFData(indexName, header, reader.iterator(), renewLock);
        }

        waitUntilAllShardsStarted(indexName, MAX_WAIT_TIME_FOR_REPLICATION_TO_COMPLETE_IN_MILLIS);
        Instant endTime = Instant.now();
        updateDatasourceAsSucceeded(indexName, datasource, manifest, fieldsToStore, startTime, endTime);
    }


    /**
     * We wait until all shards are ready to serve search requests before updating datasource metadata to
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
     * Return header fields of threat intel feed data with given url of a manifest file
     *
     * The first column is ip range field regardless its header name.
     * Therefore, we don't store the first column's header name.
     *
     * @param manifestUrl the url of a manifest file
     * @return header fields of ioc data
     */
    public List<String> getHeaderFields(String manifestUrl) throws IOException {
        URL url = new URL(manifestUrl);
        DatasourceManifest manifest = DatasourceManifest.Builder.build(url);

        try (CSVParser reader = threatIntelFeedDao.getDatabaseReader(manifest)) {
            String[] fields = reader.iterator().next().values();
            return Arrays.asList(fields).subList(1, fields.length);
        }
    }

    /**
     * Delete all indices except the one which are being used
     *
     * @param datasource
     */
    public void deleteUnusedIndices(final Datasource datasource) {
        try {
            List<String> indicesToDelete = datasource.getIndices()
                    .stream()
                    .filter(index -> index.equals(datasource.currentIndexName()) == false)
                    .collect(Collectors.toList());

            List<String> deletedIndices = deleteIndices(indicesToDelete);

            if (deletedIndices.isEmpty() == false) {
                datasource.getIndices().removeAll(deletedIndices);
                datasourceDao.updateDatasource(datasource);
            }
        } catch (Exception e) {
            log.error("Failed to delete old indices for {}", datasource.getName(), e);
        }
    }

    /**
     * Update datasource with given systemSchedule and task
     *
     * @param datasource datasource to update
     * @param systemSchedule new system schedule value
     * @param task new task value
     */
    public void updateDatasource(final Datasource datasource, final IntervalSchedule systemSchedule, final DatasourceTask task) {
        boolean updated = false;

        if (datasource.getTask().equals(task) == false) {
            datasource.setTask(task);
            updated = true;
        }

        if (updated) {
            datasourceDao.updateDatasource(datasource);
        }
    } //TODO

    private List<String> deleteIndices(final List<String> indicesToDelete) {
        List<String> deletedIndices = new ArrayList<>(indicesToDelete.size());
        for (String index : indicesToDelete) {
            if (clusterService.state().metadata().hasIndex(index) == false) {
                deletedIndices.add(index);
                continue;
            }

            try {
                threatIntelFeedDao.deleteThreatIntelDataIndex(index);
                deletedIndices.add(index);
            } catch (Exception e) {
                log.error("Failed to delete an index [{}]", index, e);
            }
        }
        return deletedIndices;
    }

    /**
     * Validate header
     *
     * 1. header should not be null
     * 2. the number of values in header should be more than one
     *
     * @param header the header
     * @return CSVRecord the input header
     */
    private CSVRecord validateHeader(CSVRecord header) {
        if (header == null) {
            throw new OpenSearchException("threat intel feed database is empty");
        }
        if (header.values().length < 2) {
            throw new OpenSearchException("threat intel feed database should have at least two fields");
        }
        return header;
    }

    /***
     * Update datasource as succeeded
     *
     * @param manifest the manifest
     * @param datasource the datasource
     */
    private void updateDatasourceAsSucceeded(
            final String newIndexName,
            final Datasource datasource,
            final DatasourceManifest manifest,
            final List<String> fields,
            final Instant startTime,
            final Instant endTime
    ) {
        datasource.setCurrentIndex(newIndexName);
        datasource.setDatabase(manifest, fields);
        datasource.getUpdateStats().setLastSucceededAt(endTime);
        datasource.getUpdateStats().setLastProcessingTimeInMillis(endTime.toEpochMilli() - startTime.toEpochMilli());
        datasource.enable();
        datasource.setState(DatasourceState.AVAILABLE);
        datasourceDao.updateDatasource(datasource);
        log.info(
                "threat intel feed database creation succeeded for {} and took {} seconds",
                datasource.getName(),
                Duration.between(startTime, endTime)
        );
    }

    /***
     * Setup index to add a new threat intel feed data
     *
     * @param datasource the datasource
     * @return new index name
     */
    private String setupIndex(final Datasource datasource) {
        String indexName = datasource.newIndexName(UUID.randomUUID().toString());
        datasource.getIndices().add(indexName);
        datasourceDao.updateDatasource(datasource);
        threatIntelFeedDao.createIndexIfNotExists(indexName);
        return indexName;
    }

    /**
     * Determine if update is needed or not
     *
     * Update is needed when all following conditions are met
     * 1. updatedAt value in datasource is equal or before updateAt value in manifest
     * 2. SHA256 hash value in datasource is different with SHA256 hash value in manifest
     *
     * @param datasource
     * @param manifest
     * @return
     */
    private boolean shouldUpdate(final Datasource datasource, final DatasourceManifest manifest) {
        if (datasource.getDatabase().getUpdatedAt() != null
                && datasource.getDatabase().getUpdatedAt().toEpochMilli() > manifest.getUpdatedAt()) {
            return false;
        }

        if (manifest.getSha256Hash().equals(datasource.getDatabase().getSha256Hash())) {
            return false;
        }
        return true;
    }
}
