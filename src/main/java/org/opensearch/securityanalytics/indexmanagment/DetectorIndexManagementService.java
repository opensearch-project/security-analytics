/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.indexmanagment;

import com.carrotsearch.hppc.cursors.ObjectCursor;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.cluster.state.ClusterStateRequest;
import org.opensearch.action.admin.cluster.state.ClusterStateResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.component.AbstractLifecycleComponent;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;


import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_ENABLED;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_ROLLOVER_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_ENABLED;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_ROLLOVER_PERIOD;

public class DetectorIndexManagementService extends AbstractLifecycleComponent implements ClusterStateListener {

    private Logger logger = LogManager.getLogger(DetectorIndexManagementService.class);

    private final Client client;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private Settings settings;

    private volatile Boolean alertHistoryEnabled;
    private volatile Boolean findingHistoryEnabled;

    private volatile Long alertHistoryMaxDocs;
    private volatile Long findingHistoryMaxDocs;

    private volatile TimeValue alertHistoryMaxAge;
    private volatile TimeValue findingHistoryMaxAge;

    private volatile TimeValue alertHistoryRolloverPeriod;
    private volatile TimeValue findingHistoryRolloverPeriod;

    private volatile TimeValue alertHistoryRetentionPeriod;
    private volatile TimeValue findingHistoryRetentionPeriod;

    private volatile boolean isClusterManager = false;

    private Scheduler.Cancellable scheduledAlertsRollover = null;
    private Scheduler.Cancellable scheduledFindingsRollover = null;

    List<HistoryIndexInfo> alertHistoryIndices = new ArrayList<>();
    List<HistoryIndexInfo> findingHistoryIndices = new ArrayList<>();

    @Inject
    public DetectorIndexManagementService(Settings settings, Client client, ThreadPool threadPool, ClusterService clusterService) {
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;

        clusterService.addListener(this);

        clusterService.getClusterSettings().addSettingsUpdateConsumer(ALERT_HISTORY_ENABLED, this::setAlertHistoryEnabled);
        clusterService.getClusterSettings().addSettingsUpdateConsumer(ALERT_HISTORY_MAX_DOCS, maxDocs -> {
            setAlertHistoryMaxDocs(maxDocs);
            for (HistoryIndexInfo h : alertHistoryIndices) {
                h.maxDocs = maxDocs;
            }
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(ALERT_HISTORY_INDEX_MAX_AGE, maxAge -> {
            setAlertHistoryMaxAge(maxAge);
            for (HistoryIndexInfo h : alertHistoryIndices) {
                h.maxAge = maxAge;
            }
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(ALERT_HISTORY_ROLLOVER_PERIOD, timeValue -> {
            DetectorIndexManagementService.this.alertHistoryRolloverPeriod = timeValue;
            rescheduleAlertRollover();
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(ALERT_HISTORY_RETENTION_PERIOD, this::setAlertHistoryRetentionPeriod);

        clusterService.getClusterSettings().addSettingsUpdateConsumer(FINDING_HISTORY_ENABLED, this::setFindingHistoryEnabled);
        clusterService.getClusterSettings().addSettingsUpdateConsumer(FINDING_HISTORY_MAX_DOCS, maxDocs -> {
            setFindingHistoryMaxDocs(maxDocs);
            for (HistoryIndexInfo h : findingHistoryIndices) {
                h.maxDocs = maxDocs;
            }
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(FINDING_HISTORY_INDEX_MAX_AGE, maxAge -> {
            setFindingHistoryMaxAge(maxAge);
            for (HistoryIndexInfo h : findingHistoryIndices) {
                h.maxAge = maxAge;
            }
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(FINDING_HISTORY_ROLLOVER_PERIOD, timeValue -> {
            DetectorIndexManagementService.this.findingHistoryRolloverPeriod = timeValue;
            rescheduleFindingRollover();
        });
        clusterService.getClusterSettings().addSettingsUpdateConsumer(FINDING_HISTORY_RETENTION_PERIOD, this::setFindingHistoryRetentionPeriod);

        initFromClusterSettings();

        initAllIndexLists();
    }

    private void initAllIndexLists() {
        Arrays.stream(Detector.DetectorType.values()).forEach(
                detectorType -> {

                    String alertsHistoryIndex = DetectorMonitorConfig.getAlertsHistoryIndex(detectorType.getDetectorType());
                    String alertsHistoryIndexPattern = DetectorMonitorConfig.getAlertsHistoryIndexPattern(detectorType.getDetectorType());

                    alertHistoryIndices.add(new HistoryIndexInfo(
                            alertsHistoryIndex,
                            alertsHistoryIndexPattern,
                            alertMapping(),
                            alertHistoryMaxDocs,
                            alertHistoryMaxAge,
                            false
                    ));

                    String findingsIndex = DetectorMonitorConfig.getFindingsIndex(detectorType.getDetectorType());
                    String findingsIndexPattern = DetectorMonitorConfig.getFindingsIndexPattern(detectorType.getDetectorType());

                    findingHistoryIndices.add(new HistoryIndexInfo(
                            findingsIndex,
                            findingsIndexPattern,
                            findingMapping(),
                            findingHistoryMaxDocs,
                            findingHistoryMaxAge,
                            false
                    ));
                });
    }

    private void initFromClusterSettings() {
        alertHistoryEnabled = ALERT_HISTORY_ENABLED.get(settings);
        findingHistoryEnabled = FINDING_HISTORY_ENABLED.get(settings);
        alertHistoryMaxDocs = ALERT_HISTORY_MAX_DOCS.get(settings);
        findingHistoryMaxDocs = FINDING_HISTORY_MAX_DOCS.get(settings);
        alertHistoryMaxAge = ALERT_HISTORY_INDEX_MAX_AGE.get(settings);
        findingHistoryMaxAge = FINDING_HISTORY_INDEX_MAX_AGE.get(settings);
        alertHistoryRolloverPeriod = ALERT_HISTORY_ROLLOVER_PERIOD.get(settings);
        findingHistoryRolloverPeriod = FINDING_HISTORY_ROLLOVER_PERIOD.get(settings);
        alertHistoryRetentionPeriod = ALERT_HISTORY_RETENTION_PERIOD.get(settings);
        findingHistoryRetentionPeriod = FINDING_HISTORY_RETENTION_PERIOD.get(settings);
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // Instead of using a LocalNodeClusterManagerListener to track master changes, this service will
        // track them here to avoid conditions where master listener events run after other
        // listeners that depend on what happened in the master listener
        if (this.isClusterManager != event.localNodeClusterManager()) {
            this.isClusterManager = event.localNodeClusterManager();
            if (this.isClusterManager) {
                onMaster();
            } else {
                offMaster();
            }
        }
        for (HistoryIndexInfo h : alertHistoryIndices) {
            h.isInitialized = event.state().metadata().hasAlias(h.indexAlias);
        }
        for (HistoryIndexInfo h : findingHistoryIndices) {
            h.isInitialized = event.state().metadata().hasAlias(h.indexAlias);
        }
    }

    private void onMaster() {
        try {
            // try to rollover immediately as we might be restarting the cluster
            rolloverAlertHistoryIndices();
            rolloverFindingHistoryIndices();
            // schedule the next rollover for approx MAX_AGE later
            scheduledAlertsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteAlertHistoryIndices(), alertHistoryRolloverPeriod, executorName());
            scheduledFindingsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteFindingHistoryIndices(), findingHistoryRolloverPeriod, executorName());
        } catch (Exception e) {
            // This should be run on cluster startup
            logger.error(
                    "Error creating alert/finding indices. " +
                            "Alerts/Findings can't be recorded until master node is restarted.",
                    e
            );
        }
    }

    private void offMaster() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
    }

    private String executorName() {
        return ThreadPool.Names.MANAGEMENT;
    }

    private void deleteOldIndices(String tag, String... indices) {
        logger.error("info deleteOldIndices");
        ClusterStateRequest clusterStateRequest = new ClusterStateRequest()
                .clear()
                .indices(indices)
                .metadata(true)
                .local(true)
                .indicesOptions(IndicesOptions.strictExpand());
        client.admin().cluster().state(
                clusterStateRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(ClusterStateResponse clusterStateResponse) {
                        if (!clusterStateResponse.getState().metadata().getIndices().isEmpty()) {
                            List<String> indicesToDelete = getIndicesToDelete(clusterStateResponse);
                            logger.info("Checking if we should delete " + tag + " indices: [" + indicesToDelete + "]");
                            deleteAllOldHistoryIndices(indicesToDelete);
                        } else {
                            logger.info("No Old " + tag + " Indices to delete");
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        logger.error("Error fetching cluster state");
                    }
                }
        );
    }

    private List<String> getIndicesToDelete(ClusterStateResponse clusterStateResponse) {
        List<String> indicesToDelete = new ArrayList<>();
        for (IndexMetadata indexMetadata : clusterStateResponse.getState().metadata().indices().values()) {
            IndexMetadata indexMetaData = indexMetadata;
            String indexToDelete = getHistoryIndexToDelete(indexMetaData, alertHistoryRetentionPeriod.millis(), alertHistoryIndices, alertHistoryEnabled);
            if (indexToDelete != null) {
                indicesToDelete.add(indexToDelete);
            }
            indexToDelete = getHistoryIndexToDelete(indexMetaData, findingHistoryRetentionPeriod.millis(), findingHistoryIndices, findingHistoryEnabled);
            if (indexToDelete != null) {
                indicesToDelete.add(indexToDelete);
            }
        }
        return indicesToDelete;
    }

    private String getHistoryIndexToDelete(
            IndexMetadata indexMetadata,
            Long retentionPeriodMillis,
            List<HistoryIndexInfo> historyIndices,
            Boolean historyEnabled
    ) {
        long creationTime = indexMetadata.getCreationDate();
        if ((Instant.now().toEpochMilli() - creationTime) > retentionPeriodMillis) {
            String alias = null;
            for (AliasMetadata aliasMetadata : indexMetadata.getAliases().values()) {
                Optional<HistoryIndexInfo> historyIndexInfoOptional = historyIndices
                        .stream()
                        .filter(e -> e.indexAlias.equals(aliasMetadata.alias()))
                        .findFirst();
                if (historyIndexInfoOptional.isPresent()) {
                    alias = historyIndexInfoOptional.get().indexAlias;
                    break;
                }
            }
            if (alias != null) {
                if (historyEnabled) {
                    // If the index has the write alias and history is enabled, don't delete the index
                    return null;
                }
            }
            return indexMetadata.getIndex().getName();
        }
        return null;
    }

    private void deleteAllOldHistoryIndices(List<String> indicesToDelete) {
        if (indicesToDelete.size() > 0) {
            DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indicesToDelete.toArray(new String[0]));
            client.admin().indices().delete(
                    deleteIndexRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse deleteIndicesResponse) {
                            if (!deleteIndicesResponse.isAcknowledged()) {
                                logger.error(
                                        "Could not delete one or more Alerting/Finding history indices: [" + indicesToDelete + "]. Retrying one by one."
                                );
                                deleteOldHistoryIndex(indicesToDelete);
                            } else {
                                logger.info("Succsessfuly deleted indices: [" + indicesToDelete + "]");
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            logger.error("Delete for Alerting/Finding History Indices failed: [" + indicesToDelete + "]. Retrying one By one.");
                            deleteOldHistoryIndex(indicesToDelete);
                        }
                    }
            );
        }
    }

    private void deleteOldHistoryIndex(List<String> indicesToDelete) {
        for (String index : indicesToDelete) {
            final DeleteIndexRequest singleDeleteRequest = new DeleteIndexRequest(indicesToDelete.toArray(new String[0]));

            client.admin().indices().delete(
                    singleDeleteRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                            if (!acknowledgedResponse.isAcknowledged()) {
                                logger.error("Could not delete one or more Alerting/Finding history indices: " + index);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            logger.debug("Exception: [" + e.getMessage() + "] while deleting the index " + index);
                        }
                    }
            );
        }
    }

    private void rolloverAndDeleteAlertHistoryIndices() {
        if (alertHistoryEnabled) rolloverAlertHistoryIndices();
        deleteOldIndices("Alert", DetectorMonitorConfig.getAllAlertsIndicesPatternForAllTypes().toArray(new String[0]));
    }

    private void rolloverAndDeleteFindingHistoryIndices() {
        if (findingHistoryEnabled) rolloverFindingHistoryIndices();
        deleteOldIndices("Finding", DetectorMonitorConfig.getAllFindingsIndicesPatternForAllTypes().toArray(new String[0]));
    }

    private void rolloverIndex(
            Boolean initialized,
            String index,
            String pattern,
            String map,
            Long docsCondition,
            TimeValue ageCondition
    ) {
        if (!initialized) {
            return;
        }

        // We have to pass null for newIndexName in order to get Elastic to increment the index count.
        RolloverRequest request = new RolloverRequest(index, null);
        request.getCreateIndexRequest().index(pattern)
                .mapping(map)
                .settings(Settings.builder().put("index.hidden", true).build());
        request.addMaxIndexDocsCondition(docsCondition);
        request.addMaxIndexAgeCondition(ageCondition);
        client.admin().indices().rolloverIndex(
                request,
                new ActionListener<>() {
                    @Override
                    public void onResponse(RolloverResponse rolloverResponse) {
                        if (!rolloverResponse.isRolledOver()) {
                            logger.info(index + "not rolled over. Conditions were: " + rolloverResponse.getConditionStatus());
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        logger.error("rollover failed for index [" + index + "].");
                    }
                }
        );
    }

    private void rolloverAlertHistoryIndices() {
        for(HistoryIndexInfo h : alertHistoryIndices) {
            rolloverIndex(
                h.isInitialized, h.indexAlias,
                h.indexPattern, h.indexMappings,
                h.maxDocs, h.maxAge
            );
        }
    }
    private void rolloverFindingHistoryIndices() {
        for (HistoryIndexInfo h : findingHistoryIndices) {
            rolloverIndex(
                h.isInitialized, h.indexAlias,
                h.indexPattern, h.indexMappings,
                h.maxDocs, h.maxAge
            );
        }
    }

    private void rescheduleAlertRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedMaster()) {
            if (scheduledAlertsRollover != null) {
                scheduledAlertsRollover.cancel();
            }
            scheduledAlertsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteAlertHistoryIndices(), alertHistoryRolloverPeriod, executorName());
        }
    }

    private void rescheduleFindingRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedMaster()) {
            if (scheduledFindingsRollover != null) {
                scheduledFindingsRollover.cancel();
            }
            scheduledFindingsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteFindingHistoryIndices(), findingHistoryRolloverPeriod, executorName());
        }
    }

    private String alertMapping() {
        String alertMapping = null;
        try (
                InputStream is = DetectorIndexManagementService.class.getClassLoader().getResourceAsStream("mappings/alert_mapping.json")
        ) {
            alertMapping = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return alertMapping;
    }

    private String findingMapping() {
        String findingMapping = null;
        try (
                InputStream is = DetectorIndexManagementService.class.getClassLoader().getResourceAsStream("mappings/finding_mapping.json")
        ) {
            findingMapping = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return findingMapping;
    }

    // Setters

    public void setAlertHistoryEnabled(Boolean alertHistoryEnabled) {
        this.alertHistoryEnabled = alertHistoryEnabled;
    }

    public void setFindingHistoryEnabled(Boolean findingHistoryEnabled) {
        this.findingHistoryEnabled = findingHistoryEnabled;
    }

    public void setAlertHistoryMaxDocs(Long alertHistoryMaxDocs) {
        this.alertHistoryMaxDocs = alertHistoryMaxDocs;
    }

    public void setFindingHistoryMaxDocs(Long findingHistoryMaxDocs) {
        this.findingHistoryMaxDocs = findingHistoryMaxDocs;
    }

    public void setAlertHistoryMaxAge(TimeValue alertHistoryMaxAge) {
        this.alertHistoryMaxAge = alertHistoryMaxAge;
    }

    public void setFindingHistoryMaxAge(TimeValue findingHistoryMaxAge) {
        this.findingHistoryMaxAge = findingHistoryMaxAge;
    }

    public void setAlertHistoryRolloverPeriod(TimeValue alertHistoryRolloverPeriod) {
        this.alertHistoryRolloverPeriod = alertHistoryRolloverPeriod;
    }

    public void setFindingHistoryRolloverPeriod(TimeValue findingHistoryRolloverPeriod) {
        this.findingHistoryRolloverPeriod = findingHistoryRolloverPeriod;
    }

    public void setAlertHistoryRetentionPeriod(TimeValue alertHistoryRetentionPeriod) {
        this.alertHistoryRetentionPeriod = alertHistoryRetentionPeriod;
    }

    public void setFindingHistoryRetentionPeriod(TimeValue findingHistoryRetentionPeriod) {
        this.findingHistoryRetentionPeriod = findingHistoryRetentionPeriod;
    }

    public void setClusterManager(boolean clusterManager) {
        isClusterManager = clusterManager;
    }

    @Override
    protected void doStart() {

    }

    @Override
    protected void doStop() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
    }

    @Override
    protected void doClose() {
        if (scheduledAlertsRollover != null) {
            scheduledAlertsRollover.cancel();
        }
        if (scheduledFindingsRollover != null) {
            scheduledFindingsRollover.cancel();
        }
    }

    private static class HistoryIndexInfo {

        String indexAlias;
        String indexPattern;
        String indexMappings;
        Long maxDocs;
        TimeValue maxAge;
        boolean isInitialized;

        public HistoryIndexInfo(String indexAlias, String indexPattern, String indexMappings, Long maxDocs, TimeValue maxAge, boolean isInitialized) {
            this.indexAlias = indexAlias;
            this.indexPattern = indexPattern;
            this.indexMappings = indexMappings;
            this.maxDocs = maxDocs;
            this.maxAge = maxAge;
            this.isInitialized = isInitialized;
        }
    }
}
