/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.indexmanagment;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.admin.cluster.state.ClusterStateRequest;
import org.opensearch.action.admin.cluster.state.ClusterStateResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterManagerThrottlingException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.snapshots.SnapshotInProgressException;
import org.opensearch.threadpool.Scheduler;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.*;

public class DetectorIndexManagementService extends AbstractLifecycleComponent implements ClusterStateListener {

    private Logger logger = LogManager.getLogger(DetectorIndexManagementService.class);

    private final Client client;
    private final ThreadPool threadPool;

    // Deleting an index fails while it is part of an in-progress snapshot. Snapshots of large clusters routinely run
    // for several minutes, so blocked deletes are retried with exponential backoff (5, 10 and 20 minutes).
    static final int MAX_HISTORY_DELETE_RETRIES = 3;
    static final TimeValue HISTORY_DELETE_RETRY_BASE_DELAY = TimeValue.timeValueMinutes(5);
    private final ClusterService clusterService;
    private final LogTypeService logTypeService;
    private Settings settings;

    private volatile Boolean alertHistoryEnabled;
    private volatile Boolean findingHistoryEnabled;

    private volatile Boolean iocFindingHistoryEnabled;

    private volatile Long alertHistoryMaxDocs;
    private volatile Long findingHistoryMaxDocs;

    private volatile Long iocFindingHistoryMaxDocs;

    private volatile Long correlationHistoryMaxDocs;

    private volatile TimeValue alertHistoryMaxAge;
    private volatile TimeValue findingHistoryMaxAge;

    private volatile TimeValue correlationHistoryMaxAge;

    private volatile TimeValue iocFindingHistoryMaxAge;

    private volatile TimeValue alertHistoryRolloverPeriod;
    private volatile TimeValue findingHistoryRolloverPeriod;

    private volatile TimeValue correlationHistoryRolloverPeriod;

    private volatile TimeValue iocFindingHistoryRolloverPeriod;

    private volatile TimeValue alertHistoryRetentionPeriod;
    private volatile TimeValue findingHistoryRetentionPeriod;

    private volatile TimeValue correlationHistoryRetentionPeriod;

    private volatile TimeValue iocFindingHistoryRetentionPeriod;

    private volatile boolean isClusterManager = false;

    private Scheduler.Cancellable scheduledAlertsRollover = null;
    private Scheduler.Cancellable scheduledFindingsRollover = null;

    private Scheduler.Cancellable scheduledCorrelationHistoryRollover = null;

    private Scheduler.Cancellable scheduledIocFindingHistoryRollover = null;

    List<HistoryIndexInfo> alertHistoryIndices = new ArrayList<>();
    List<HistoryIndexInfo> findingHistoryIndices = new ArrayList<>();

    HistoryIndexInfo correlationHistoryIndex = null;

    HistoryIndexInfo iocFindingHistoryIndex = null;

    @Inject
    public DetectorIndexManagementService(
            Settings settings,
            Client client,
            ThreadPool threadPool,
            ClusterService clusterService,
            LogTypeService logTypeService
    ) {
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.logTypeService = logTypeService;

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

        clusterService.getClusterSettings().addSettingsUpdateConsumer(CORRELATION_HISTORY_MAX_DOCS, maxDocs -> {
            setCorrelationHistoryMaxDocs(maxDocs);
            if (correlationHistoryIndex != null) {
                correlationHistoryIndex.maxDocs = maxDocs;
            }
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(CORRELATION_HISTORY_INDEX_MAX_AGE, maxAge -> {
            setCorrelationHistoryMaxAge(maxAge);
            if (correlationHistoryIndex != null) {
                correlationHistoryIndex.maxAge = maxAge;
            }
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(CORRELATION_HISTORY_ROLLOVER_PERIOD, timeValue -> {
            DetectorIndexManagementService.this.correlationHistoryRolloverPeriod = timeValue;
            rescheduleCorrelationHistoryRollover();
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(CORRELATION_HISTORY_RETENTION_PERIOD, this::setCorrelationHistoryRetentionPeriod);

        clusterService.getClusterSettings().addSettingsUpdateConsumer(IOC_FINDING_HISTORY_MAX_DOCS, maxDocs -> {
            setIocFindingHistoryMaxDocs(maxDocs);
            if (iocFindingHistoryIndex != null) {
                iocFindingHistoryIndex.maxDocs = maxDocs;
            }
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(IOC_FINDING_HISTORY_INDEX_MAX_AGE, maxAge -> {
            setIocFindingHistoryMaxAge(maxAge);
            if (iocFindingHistoryIndex != null) {
                iocFindingHistoryIndex.maxAge = maxAge;
            }
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(IOC_FINDING_HISTORY_ROLLOVER_PERIOD, timeValue -> {
            DetectorIndexManagementService.this.iocFindingHistoryRolloverPeriod = timeValue;
            rescheduleIocFindingHistoryRollover();
        });

        clusterService.getClusterSettings().addSettingsUpdateConsumer(IOC_FINDING_HISTORY_RETENTION_PERIOD, this::setIocFindingHistoryRetentionPeriod);

        initFromClusterSettings();
    }

    private void populateAllIndexLists(List<String> logTypes) {

        alertHistoryIndices.clear();
        findingHistoryIndices.clear();

        logTypes.forEach(
                logType -> {

                    String alertsHistoryIndex = DetectorMonitorConfig.getAlertsHistoryIndex(logType);
                    String alertsHistoryIndexPattern = DetectorMonitorConfig.getAlertsHistoryIndexPattern(logType);

                    alertHistoryIndices.add(new HistoryIndexInfo(
                            alertsHistoryIndex,
                            alertsHistoryIndexPattern,
                            alertMapping(),
                            alertHistoryMaxDocs,
                            alertHistoryMaxAge,
                            clusterService.state().metadata().hasAlias(alertsHistoryIndex)
                    ));

                    String findingsIndex = DetectorMonitorConfig.getFindingsIndex(logType);
                    String findingsIndexPattern = DetectorMonitorConfig.getFindingsIndexPattern(logType);

                    findingHistoryIndices.add(new HistoryIndexInfo(
                            findingsIndex,
                            findingsIndexPattern,
                            findingMapping(),
                            findingHistoryMaxDocs,
                            findingHistoryMaxAge,
                            clusterService.state().metadata().hasAlias(findingsIndex)
                    ));
                });
    }

    private void initFromClusterSettings() {
        alertHistoryEnabled = ALERT_HISTORY_ENABLED.get(settings);
        findingHistoryEnabled = FINDING_HISTORY_ENABLED.get(settings);
        alertHistoryMaxDocs = ALERT_HISTORY_MAX_DOCS.get(settings);
        findingHistoryMaxDocs = FINDING_HISTORY_MAX_DOCS.get(settings);
        correlationHistoryMaxDocs = CORRELATION_HISTORY_MAX_DOCS.get(settings);
        iocFindingHistoryMaxDocs = IOC_FINDING_HISTORY_MAX_DOCS.get(settings);
        alertHistoryMaxAge = ALERT_HISTORY_INDEX_MAX_AGE.get(settings);
        findingHistoryMaxAge = FINDING_HISTORY_INDEX_MAX_AGE.get(settings);
        correlationHistoryMaxAge = CORRELATION_HISTORY_INDEX_MAX_AGE.get(settings);
        iocFindingHistoryMaxAge = IOC_FINDING_HISTORY_INDEX_MAX_AGE.get(settings);
        alertHistoryRolloverPeriod = ALERT_HISTORY_ROLLOVER_PERIOD.get(settings);
        findingHistoryRolloverPeriod = FINDING_HISTORY_ROLLOVER_PERIOD.get(settings);
        correlationHistoryRolloverPeriod = CORRELATION_HISTORY_ROLLOVER_PERIOD.get(settings);
        iocFindingHistoryRolloverPeriod = IOC_FINDING_HISTORY_ROLLOVER_PERIOD.get(settings);
        alertHistoryRetentionPeriod = ALERT_HISTORY_RETENTION_PERIOD.get(settings);
        findingHistoryRetentionPeriod = FINDING_HISTORY_RETENTION_PERIOD.get(settings);
        correlationHistoryRetentionPeriod = CORRELATION_HISTORY_RETENTION_PERIOD.get(settings);
        iocFindingHistoryRetentionPeriod = IOC_FINDING_HISTORY_RETENTION_PERIOD.get(settings);
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

        if (correlationHistoryIndex != null && correlationHistoryIndex.indexAlias != null) {
            correlationHistoryIndex.isInitialized = event.state().metadata().hasAlias(correlationHistoryIndex.indexAlias);
        }
        if (iocFindingHistoryIndex != null && iocFindingHistoryIndex.indexAlias != null) {
            iocFindingHistoryIndex.isInitialized = event.state().metadata().hasAlias(iocFindingHistoryIndex.indexAlias);
        }
    }

    private void onMaster() {
        try {
            // try to rollover immediately as we might be restarting the cluster
            threadPool.schedule(() -> {
                rolloverAndDeleteAlertHistoryIndices();
                rolloverAndDeleteFindingHistoryIndices();
                rolloverAndDeleteCorrelationHistoryIndices();
                rolloverAndDeleteIocFindingHistoryIndices();
            }, TimeValue.timeValueSeconds(1), executorName());
            // schedule the next rollover for approx MAX_AGE later
            scheduledAlertsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteAlertHistoryIndices(), alertHistoryRolloverPeriod, executorName());
            scheduledFindingsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteFindingHistoryIndices(), findingHistoryRolloverPeriod, executorName());
            scheduledCorrelationHistoryRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteCorrelationHistoryIndices(), correlationHistoryRolloverPeriod, executorName());
            scheduledIocFindingHistoryRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteIocFindingHistoryIndices(), iocFindingHistoryRolloverPeriod, executorName());
        } catch (Exception e) {
            // This should be run on cluster startup
            logger.error(
                    "Error creating alert/finding/correlation/ioc finding indices. " +
                            "Alerts/Findings/Correlations/IOC Finding can't be recorded until master node is restarted.",
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
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
        if (scheduledIocFindingHistoryRollover != null) {
            scheduledIocFindingHistoryRollover.cancel();
        }
    }

    private String executorName() {
        return ThreadPool.Names.MANAGEMENT;
    }

    /**
     * Deletes the history indices of a single history type that are older than that type's retention period.
     * Each history type (alerts, findings, correlation, IOC findings) is evaluated only against its own retention
     * period and its own write aliases, so an index of one type is never selected by another type's retention.
     */
    private void deleteOldIndices(
            String tag,
            TimeValue retentionPeriod,
            List<HistoryIndexInfo> historyIndices,
            boolean historyEnabled,
            String... indices
    ) {
        logger.info("info deleteOldIndices");
        final long retentionPeriodMillis = retentionPeriod.millis();
        final Set<String> historyAliases = historyIndices
                .stream()
                .map(h -> h.indexAlias)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
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
                            List<String> indicesToDelete = getIndicesToDelete(
                                    clusterStateResponse.getState().metadata().indices().values(),
                                    Instant.now().toEpochMilli(),
                                    retentionPeriodMillis,
                                    historyAliases,
                                    historyEnabled
                            );
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

    static List<String> getIndicesToDelete(
            Collection<IndexMetadata> indicesMetadata,
            long nowMillis,
            long retentionPeriodMillis,
            Set<String> historyAliases,
            boolean historyEnabled
    ) {
        List<String> indicesToDelete = new ArrayList<>();
        for (IndexMetadata indexMetadata : indicesMetadata) {
            String indexToDelete = getHistoryIndexToDelete(indexMetadata, nowMillis, retentionPeriodMillis, historyAliases, historyEnabled);
            if (indexToDelete != null) {
                indicesToDelete.add(indexToDelete);
            }
        }
        return indicesToDelete;
    }

    static String getHistoryIndexToDelete(
            IndexMetadata indexMetadata,
            long nowMillis,
            long retentionPeriodMillis,
            Set<String> historyAliases,
            boolean historyEnabled
    ) {
        if ((nowMillis - indexMetadata.getCreationDate()) <= retentionPeriodMillis) {
            return null;
        }
        boolean isCurrentWriteIndex = indexMetadata.getAliases().keySet().stream().anyMatch(historyAliases::contains);
        if (isCurrentWriteIndex && historyEnabled) {
            // The index still holds the history write alias and history is enabled, so it must not be deleted
            return null;
        }
        return indexMetadata.getIndex().getName();
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
                                        "Could not delete one or more Alerting/Finding/Correlation/IOC Finding history indices: [" + indicesToDelete + "]. Retrying one by one."
                                );
                                deleteOldHistoryIndex(indicesToDelete);
                            } else {
                                logger.info("Succsessfuly deleted indices: [" + indicesToDelete + "]");
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            logger.error("Delete for Alerting/Finding/Correlation/IOC Finding History Indices failed: [" + indicesToDelete + "]. Retrying one By one.");
                            deleteOldHistoryIndex(indicesToDelete);
                        }
                    }
            );
        }
    }

    private void deleteOldHistoryIndex(List<String> indicesToDelete) {
        for (String index : indicesToDelete) {
            deleteSingleHistoryIndex(index, 0);
        }
    }

    private void deleteSingleHistoryIndex(String index, int attempt) {
        // One index per request, so that a single index that cannot be deleted does not fail the others.
        client.admin().indices().delete(
                new DeleteIndexRequest(index),
                new ActionListener<>() {
                    @Override
                    public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                        if (!acknowledgedResponse.isAcknowledged()) {
                            logger.error("Could not delete Alerting/Finding/Correlation/IOC Finding history index: " + index);
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        if (isRetryableHistoryDeleteFailure(e) && attempt < MAX_HISTORY_DELETE_RETRIES) {
                            TimeValue delay = historyDeleteRetryDelay(attempt);
                            logger.warn(
                                    "Deleting history index [{}] was blocked by [{}], retry {}/{} in {}",
                                    index,
                                    ExceptionsHelper.unwrapCause(e).getClass().getSimpleName(),
                                    attempt + 1,
                                    MAX_HISTORY_DELETE_RETRIES,
                                    delay
                            );
                            threadPool.schedule(() -> deleteSingleHistoryIndex(index, attempt + 1), delay, executorName());
                        } else {
                            logger.warn("Failed to delete history index [" + index + "] after " + (attempt + 1) + " attempt(s)", e);
                        }
                    }
                }
        );
    }

    /**
     * Exponential backoff for retrying a blocked history index delete: base delay * 2^attempt (5, 10, 20 minutes).
     */
    static TimeValue historyDeleteRetryDelay(int attempt) {
        return TimeValue.timeValueMillis(HISTORY_DELETE_RETRY_BASE_DELAY.millis() << attempt);
    }

    /**
     * A delete blocked by an in-progress snapshot or by cluster-manager throttling is transient and is retried later,
     * instead of waiting a full rollover period for the next scheduled run.
     */
    static boolean isRetryableHistoryDeleteFailure(Exception e) {
        Throwable cause = ExceptionsHelper.unwrapCause(e);
        return cause instanceof SnapshotInProgressException || cause instanceof ClusterManagerThrottlingException;
    }

    private void rolloverAndDeleteAlertHistoryIndices() {
        logTypeService.getAllLogTypes(ActionListener.wrap(logTypes -> {
            if (logTypes == null || logTypes.isEmpty()) {
                return;
            }
            // We have to do this every time to account for newly added log types
            populateAllIndexLists(logTypes);

            if (alertHistoryEnabled) rolloverAlertHistoryIndices();
            deleteOldIndices(
                    "Alert",
                    alertHistoryRetentionPeriod,
                    List.copyOf(alertHistoryIndices),
                    alertHistoryEnabled,
                    getAllAlertsHistoryIndicesPatternForAllTypes(logTypes).toArray(new String[0])
            );
        }, e -> {}));
    }

    private void rolloverAndDeleteFindingHistoryIndices() {
        logTypeService.getAllLogTypes(ActionListener.wrap(logTypes -> {
            if (logTypes == null || logTypes.isEmpty()) {
                return;
            }
            // We have to do this every time to account for newly added log types
            populateAllIndexLists(logTypes);

            if (findingHistoryEnabled) rolloverFindingHistoryIndices();
            deleteOldIndices(
                    "Finding",
                    findingHistoryRetentionPeriod,
                    List.copyOf(findingHistoryIndices),
                    findingHistoryEnabled,
                    getAllFindingsIndicesPatternForAllTypes(logTypes).toArray(new String[0])
            );
        }, e -> {}));
    }

    private void rolloverAndDeleteCorrelationHistoryIndices() {
        try {
            correlationHistoryIndex = new HistoryIndexInfo(
                    CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX,
                    CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN,
                    CorrelationIndices.correlationMappings(),
                    correlationHistoryMaxDocs,
                    correlationHistoryMaxAge,
                    clusterService.state().metadata().hasAlias(CorrelationIndices.CORRELATION_HISTORY_WRITE_INDEX)
            );
            rolloverCorrelationHistoryIndices();
            deleteOldIndices(
                    "Correlation",
                    correlationHistoryRetentionPeriod,
                    List.of(correlationHistoryIndex),
                    true,
                    CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN_REGEXP
            );
        } catch (Exception ex) {
            logger.error("failed to construct correlation history index info");
        }
    }

    private void rolloverAndDeleteIocFindingHistoryIndices() {
        try {
            iocFindingHistoryIndex = new HistoryIndexInfo(
                    IocFindingService.IOC_FINDING_ALIAS_NAME,
                    IocFindingService.IOC_FINDING_INDEX_PATTERN,
                    IocFindingService.getIndexMapping(),
                    iocFindingHistoryMaxDocs,
                    iocFindingHistoryMaxAge,
                    clusterService.state().metadata().hasAlias(IocFindingService.IOC_FINDING_ALIAS_NAME)
            );
            rolloverIocFindingHistoryIndices();
            deleteOldIndices(
                    "IOC Findings",
                    iocFindingHistoryRetentionPeriod,
                    List.of(iocFindingHistoryIndex),
                    true,
                    IocFindingService.IOC_FINDING_INDEX_PATTERN_REGEXP
            );
        } catch (Exception ex) {
            logger.error("failed to construct ioc finding index info");
        }
    }

    // Only the alerts history indices are subject to retention; the active alerts index (.opensearch-sap-<type>-alerts)
    // holds active and acknowledged alerts and must never be selected for deletion.
    private List<String> getAllAlertsHistoryIndicesPatternForAllTypes(List<String> logTypes) {
        return logTypes
                .stream()
                .map(DetectorMonitorConfig::getAllAlertsHistoryIndicesPattern)
                .collect(Collectors.toList());
    }

    private List<String> getAllFindingsIndicesPatternForAllTypes(List<String> logTypes) {
        return logTypes
                .stream()
                .map(logType -> DetectorMonitorConfig.getAllFindingsIndicesPattern(logType))
                .collect(Collectors.toList());
    }


        private void rolloverIndex(
            Boolean initialized,
            String index,
            String pattern,
            String map,
            Long docsCondition,
            TimeValue ageCondition,
            Boolean isCorrelation
    ) {
        if (!initialized) {
            return;
        }

        // We have to pass null for newIndexName in order to get Elastic to increment the index count.
        RolloverRequest request = new RolloverRequest(index, null);
        request.getCreateIndexRequest().index(pattern)
                .mapping(map)
                .settings(isCorrelation?
                        Settings.builder()
                                .put("index.hidden", true)
                                .put("index.correlation", true)
                                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                                .build():
                        Settings.builder()
                                .put("index.hidden", true)
                                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                                .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                                .build()
                );
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
                h.maxDocs, h.maxAge, false
            );
        }
    }
    private void rolloverFindingHistoryIndices() {
        for (HistoryIndexInfo h : findingHistoryIndices) {
            rolloverIndex(
                h.isInitialized, h.indexAlias,
                h.indexPattern, h.indexMappings,
                h.maxDocs, h.maxAge, false
            );
        }
    }

    private void rolloverCorrelationHistoryIndices() {
        if (correlationHistoryIndex != null) {
            rolloverIndex(
                    correlationHistoryIndex.isInitialized,
                    correlationHistoryIndex.indexAlias,
                    correlationHistoryIndex.indexPattern,
                    correlationHistoryIndex.indexMappings,
                    correlationHistoryIndex.maxDocs,
                    correlationHistoryIndex.maxAge,
                    true
            );
        }
    }

    private void rolloverIocFindingHistoryIndices() {
        if (iocFindingHistoryIndex != null) {
            rolloverIndex(
                    iocFindingHistoryIndex.isInitialized,
                    iocFindingHistoryIndex.indexAlias,
                    iocFindingHistoryIndex.indexPattern,
                    iocFindingHistoryIndex.indexMappings,
                    iocFindingHistoryIndex.maxDocs,
                    iocFindingHistoryIndex.maxAge,
                    true
            );
        }
    }

    private void rescheduleAlertRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledAlertsRollover != null) {
                scheduledAlertsRollover.cancel();
            }
            scheduledAlertsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteAlertHistoryIndices(), alertHistoryRolloverPeriod, executorName());
        }
    }

    private void rescheduleFindingRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledFindingsRollover != null) {
                scheduledFindingsRollover.cancel();
            }
            scheduledFindingsRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteFindingHistoryIndices(), findingHistoryRolloverPeriod, executorName());
        }
    }

    private void rescheduleCorrelationHistoryRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledCorrelationHistoryRollover != null) {
                scheduledCorrelationHistoryRollover.cancel();
            }
            scheduledCorrelationHistoryRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteCorrelationHistoryIndices(), correlationHistoryRolloverPeriod, executorName());
        }
    }

    private void rescheduleIocFindingHistoryRollover() {
        if (clusterService.state().getNodes().isLocalNodeElectedClusterManager()) {
            if (scheduledIocFindingHistoryRollover != null) {
                scheduledIocFindingHistoryRollover.cancel();
            }
            scheduledIocFindingHistoryRollover = threadPool
                    .scheduleWithFixedDelay(() -> rolloverAndDeleteIocFindingHistoryIndices(), iocFindingHistoryRolloverPeriod, executorName());
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

    public void setCorrelationHistoryMaxDocs(Long correlationHistoryMaxDocs) {
        this.correlationHistoryMaxDocs = correlationHistoryMaxDocs;
    }

    public void setIocFindingHistoryMaxDocs(Long iocFindingHistoryMaxDocs) {
        this.iocFindingHistoryMaxDocs = iocFindingHistoryMaxDocs;
    }

    public void setAlertHistoryMaxAge(TimeValue alertHistoryMaxAge) {
        this.alertHistoryMaxAge = alertHistoryMaxAge;
    }

    public void setFindingHistoryMaxAge(TimeValue findingHistoryMaxAge) {
        this.findingHistoryMaxAge = findingHistoryMaxAge;
    }

    public void setCorrelationHistoryMaxAge(TimeValue correlationHistoryMaxAge) {
        this.correlationHistoryMaxAge = correlationHistoryMaxAge;
    }

    public void setIocFindingHistoryMaxAge(TimeValue iocFindingHistoryMaxAge) {
        this.iocFindingHistoryMaxAge = iocFindingHistoryMaxAge;
    }

    public void setAlertHistoryRolloverPeriod(TimeValue alertHistoryRolloverPeriod) {
        this.alertHistoryRolloverPeriod = alertHistoryRolloverPeriod;
    }

    public void setFindingHistoryRolloverPeriod(TimeValue findingHistoryRolloverPeriod) {
        this.findingHistoryRolloverPeriod = findingHistoryRolloverPeriod;
    }

    public void setCorrelationHistoryRolloverPeriod(TimeValue correlationHistoryRolloverPeriod) {
        this.correlationHistoryRolloverPeriod = correlationHistoryRolloverPeriod;
    }

    public void setAlertHistoryRetentionPeriod(TimeValue alertHistoryRetentionPeriod) {
        this.alertHistoryRetentionPeriod = alertHistoryRetentionPeriod;
    }

    public void setFindingHistoryRetentionPeriod(TimeValue findingHistoryRetentionPeriod) {
        this.findingHistoryRetentionPeriod = findingHistoryRetentionPeriod;
    }

    public void setCorrelationHistoryRetentionPeriod(TimeValue correlationHistoryRetentionPeriod) {
        this.correlationHistoryRetentionPeriod = correlationHistoryRetentionPeriod;
    }

    public void setIocFindingHistoryRetentionPeriod(TimeValue iocFindingHistoryRetentionPeriod) {
        this.iocFindingHistoryRetentionPeriod = iocFindingHistoryRetentionPeriod;
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
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
        if (scheduledIocFindingHistoryRollover != null) {
            scheduledIocFindingHistoryRollover.cancel();
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
        if (scheduledCorrelationHistoryRollover != null) {
            scheduledCorrelationHistoryRollover.cancel();
        }
        if (scheduledIocFindingHistoryRollover != null) {
            scheduledIocFindingHistoryRollover.cancel();
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
