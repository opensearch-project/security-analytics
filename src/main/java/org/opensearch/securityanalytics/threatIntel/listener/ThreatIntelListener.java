/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.listener;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.RestoreInProgress;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceExtension;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceTask;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;

public class ThreatIntelListener extends AbstractLifecycleComponent implements ClusterStateListener {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final int SCHEDULE_IN_MIN = 15;
    private static final int DELAY_IN_MILLIS = 10000;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final DatasourceDao datasourceDao;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;

    @Override
    public void clusterChanged(final ClusterChangedEvent event) {
        if (event.localNodeClusterManager() == false) {
            return;
        }

        for (RestoreInProgress.Entry entry : event.state().custom(RestoreInProgress.TYPE, RestoreInProgress.EMPTY)) {
            if (RestoreInProgress.State.SUCCESS.equals(entry.state()) == false) {
                continue;
            }

            if (entry.indices().stream().anyMatch(index -> DatasourceExtension.JOB_INDEX_NAME.equals(index))) {
                threadPool.generic().submit(() -> forceUpdateThreatIntelFeedData());
            }

            List<String> threatIntelDataIndices = entry.indices()
                    .stream()
                    .filter(index -> index.startsWith(THREAT_INTEL_DATA_INDEX_NAME_PREFIX))
                    .collect(Collectors.toList());
            if (threatIntelDataIndices.isEmpty() == false) {
                threadPool.generic().submit(() -> threatIntelFeedDataService.deleteThreatIntelDataIndex(threatIntelDataIndices));
            }
        }
    }

    private void forceUpdateThreatIntelFeedData() {
        datasourceDao.getAllDatasources(new ActionListener<>() {
            @Override
            public void onResponse(final List<Datasource> datasources) {
                datasources.stream().forEach(ThreatIntelListener.this::scheduleForceUpdate);
                datasourceDao.updateDatasource(datasources, new ActionListener<>() {
                    @Override
                    public void onResponse(final BulkResponse bulkItemResponses) {
                        log.info("Datasources are updated for cleanup");
                    }

                    @Override
                    public void onFailure(final Exception e) {
                        log.error("Failed to update datasource for cleanup after restoring", e);
                    }
                });
            }

            @Override
            public void onFailure(final Exception e) {
                log.error("Failed to get datasource after restoring", e);
            }
        });
    }

    /**
     *  Give a delay so that job scheduler can schedule the job right after the delay. Otherwise, it schedules
     *  the job after specified update interval.
     */
    private void scheduleForceUpdate(Datasource datasource) {
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), SCHEDULE_IN_MIN, ChronoUnit.MINUTES, DELAY_IN_MILLIS);
        datasource.resetDatabase();
        datasource.setSchedule(schedule);
        datasource.setTask(DatasourceTask.ALL);
    }

    @Override
    protected void doStart() {
        if (DiscoveryNode.isClusterManagerNode(clusterService.getSettings())) {
            clusterService.addListener(this);
        }
    }

    @Override
    protected void doStop() {
        clusterService.removeListener(this);
    }

    @Override
    protected void doClose() throws IOException {

    }
}
