/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;

import org.opensearch.ingest.IngestService;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatIntel.dao.ThreatIntelFeedDao;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

/**
 * Transport action to delete datasource
 */
public class DeleteDatasourceTransportAction extends HandledTransportAction<DeleteDatasourceRequest, AcknowledgedResponse> {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final long LOCK_DURATION_IN_SECONDS = 300l;
    private final ThreatIntelLockService lockService;
    private final IngestService ingestService;
    private final DatasourceDao datasourceDao;
    private final ThreatIntelFeedDao threatIntelFeedDao;
//    private final Ip2GeoProcessorDao ip2GeoProcessorDao;
    private final ThreadPool threadPool;

    /**
     * Constructor
     * @param transportService the transport service
     * @param actionFilters the action filters
     * @param lockService the lock service
     * @param ingestService the ingest service
     * @param datasourceDao the datasource facade
     */
    @Inject
    public DeleteDatasourceTransportAction(
        final TransportService transportService,
        final ActionFilters actionFilters,
        final ThreatIntelLockService lockService,
        final IngestService ingestService,
        final DatasourceDao datasourceDao,
        final ThreatIntelFeedDao threatIntelFeedDao,
//        final Ip2GeoProcessorDao ip2GeoProcessorDao,
        final ThreadPool threadPool
    ) {
        super(DeleteDatasourceAction.NAME, transportService, actionFilters, DeleteDatasourceRequest::new);
        this.lockService = lockService;
        this.ingestService = ingestService;
        this.datasourceDao = datasourceDao;
        this.threatIntelFeedDao = threatIntelFeedDao;
//        this.ip2GeoProcessorDao = ip2GeoProcessorDao;
        this.threadPool = threadPool;
    }

    /**
     * We delete datasource regardless of its state as long as we can acquire a lock
     *
     * @param task the task
     * @param request the request
     * @param listener the listener
     */
    @Override
    protected void doExecute(final Task task, final DeleteDatasourceRequest request, final ActionListener<AcknowledgedResponse> listener) {
        lockService.acquireLock(request.getName(), LOCK_DURATION_IN_SECONDS, ActionListener.wrap(lock -> {
            if (lock == null) {
                listener.onFailure(
                        new OpenSearchStatusException("Another processor is holding a lock on the resource. Try again later", RestStatus.BAD_REQUEST)
                );
                log.error("Another processor is holding lock, BAD_REQUEST exception", RestStatus.BAD_REQUEST);

                return;
            }
            try {
                // TODO: makes every sub-methods as async call to avoid using a thread in generic pool
                threadPool.generic().submit(() -> {
                    try {
                        deleteDatasource(request.getName());
                        lockService.releaseLock(lock);
                        listener.onResponse(new AcknowledgedResponse(true));
                    } catch (Exception e) {
                        lockService.releaseLock(lock);
                        listener.onFailure(e);
                        log.error("delete data source failed",e);
                    }
                });
            } catch (Exception e) {
                lockService.releaseLock(lock);
                listener.onFailure(e);
                log.error("Internal server error", e);
            }
        }, exception -> { listener.onFailure(exception); }));
    }

    protected void deleteDatasource(final String datasourceName) throws IOException {
        Datasource datasource = datasourceDao.getDatasource(datasourceName);
        if (datasource == null) {
            throw new ResourceNotFoundException("no such datasource exist");
        }
        DatasourceState previousState = datasource.getState();
//        setDatasourceStateAsDeleting(datasource);

        try {
            threatIntelFeedDao.deleteThreatIntelDataIndex(datasource.getIndices());
        } catch (Exception e) {
            if (previousState.equals(datasource.getState()) == false) {
                datasource.setState(previousState);
                datasourceDao.updateDatasource(datasource);
            }
            throw e;
        }
        datasourceDao.deleteDatasource(datasource);
    }

//    private void setDatasourceStateAsDeleting(final Datasource datasource) {
//        if (datasourceDao.getProcessors(datasource.getName()).isEmpty() == false) {
//            throw new OpenSearchStatusException("datasource is being used by one of processors", RestStatus.BAD_REQUEST);
//        }
//
//        DatasourceState previousState = datasource.getState();
//        datasource.setState(DatasourceState.DELETING);
//        datasourceDao.updateDatasource(datasource);
//
//        // Check again as processor might just have been created.
//        // If it fails to update the state back to the previous state, the new processor
//        // will fail to convert an ip to a geo data.
//        // In such case, user have to delete the processor and delete this datasource again.
//        if (datasourceDao.getProcessors(datasource.getName()).isEmpty() == false) {
//            datasource.setState(previousState);
//            datasourceDao.updateDatasource(datasource);
//            throw new OpenSearchStatusException("datasource is being used by one of processors", RestStatus.BAD_REQUEST);
//        }
//    }
}
