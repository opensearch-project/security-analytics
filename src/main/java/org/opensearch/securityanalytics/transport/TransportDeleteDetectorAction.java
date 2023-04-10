/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.SetOnce;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorRequest;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;
import org.opensearch.securityanalytics.action.DeleteDetectorResponse;
import org.opensearch.securityanalytics.mapper.IndexTemplateManager;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;


import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportDeleteDetectorAction extends HandledTransportAction<DeleteDetectorRequest, DeleteDetectorResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteDetectorAction.class);

    private final Client client;

    private final RuleTopicIndices ruleTopicIndices;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private final IndexTemplateManager indexTemplateManager;

    private final DetectorIndices detectorIndices;

    @Inject
    public TransportDeleteDetectorAction(TransportService transportService, IndexTemplateManager indexTemplateManager, Client client, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, RuleTopicIndices ruleTopicIndices, DetectorIndices detectorIndices) {
        super(DeleteDetectorAction.NAME, transportService, actionFilters, DeleteDetectorRequest::new);
        this.client = client;
        this.ruleTopicIndices = ruleTopicIndices;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = client.threadPool();
        this.indexTemplateManager = indexTemplateManager;
        this.detectorIndices = detectorIndices;
    }

    @Override
    protected void doExecute(Task task, DeleteDetectorRequest request, ActionListener<DeleteDetectorResponse> listener) {
        AsyncDeleteDetectorAction asyncAction = new AsyncDeleteDetectorAction(task, request, listener, detectorIndices);
        asyncAction.start();
    }

    private void deleteAlertingMonitor(String monitorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteMonitorResponse> listener) {
        DeleteMonitorRequest request = new DeleteMonitorRequest(monitorId, refreshPolicy);
        AlertingPluginInterface.INSTANCE.deleteMonitor((NodeClient) client, request, listener);
    }

    private void deleteDetector(String detectorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteResponse> listener) {
        DeleteRequest request = new DeleteRequest(Detector.DETECTORS_INDEX, detectorId)
                .setRefreshPolicy(refreshPolicy);
        client.delete(request, listener);
    }

    class AsyncDeleteDetectorAction {
        private final DeleteDetectorRequest request;

        private final ActionListener<DeleteDetectorResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final DetectorIndices detectorIndices;
        private final Task task;

        AsyncDeleteDetectorAction(
                Task task,
                DeleteDetectorRequest request,
                ActionListener<DeleteDetectorResponse> listener,
                DetectorIndices detectorIndices) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
            this.detectorIndices = detectorIndices;
        }

        void start() {
            if (!detectorIndices.detectorIndexExists()) {
                onFailures(new OpenSearchStatusException(
                        String.format(Locale.getDefault(),
                                "Detector with %s is not found",
                                request.getDetectorId()),
                        RestStatus.NOT_FOUND));
                return;

            }
            TransportDeleteDetectorAction.this.threadPool.getThreadContext().stashContext();
            String detectorId = request.getDetectorId();
            GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, detectorId);
            client.get(getRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(GetResponse response) {
                            if (!response.isExists()) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", detectorId), RestStatus.NOT_FOUND));
                                return;
                            }

                            try {
                                XContentParser xcp = XContentHelper.createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                        response.getSourceAsBytesRef(), XContentType.JSON);
                                Detector detector = Detector.docParse(xcp, response.getId(), response.getVersion());
                                onGetResponse(detector);
                            } catch (Exception e) {
                                onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception t) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", detectorId), RestStatus.NOT_FOUND));
                        }
                    });
        }

        private void onGetResponse(Detector detector) {
            List<String> monitorIds = detector.getMonitorIds();
            ActionListener<DeleteMonitorResponse> deletesListener = new GroupedActionListener<>(new ActionListener<>() {
                @Override
                public void onResponse(Collection<DeleteMonitorResponse> responses) {
                    SetOnce<RestStatus> errorStatusSupplier = new SetOnce<>();
                    if (responses.stream().filter(response -> {
                        if (response.getStatus() != RestStatus.OK) {
                            log.error("Detector not being deleted because monitor [{}] could not be deleted. Status [{}]", response.getId(), response.getStatus());
                            errorStatusSupplier.trySet(response.getStatus());
                            return true;
                        }
                        return false;
                    }).count() > 0) {
                        onFailures(new OpenSearchStatusException("Monitor associated with detected could not be deleted", errorStatusSupplier.get()));
                    }
                    deleteDetectorFromConfig(detector.getId(), request.getRefreshPolicy());
                }

                @Override
                public void onFailure(Exception e) {
                    if(isOnlyMonitorOrIndexMissingExceptionThrownByGroupedActionListener(e, detector.getId())) {
                        deleteDetectorFromConfig(detector.getId(), request.getRefreshPolicy());
                    } else {
                        log.error(String.format(Locale.ROOT, "Failed to delete detector %s", detector.getId()), e);
                        if (counter.compareAndSet(false, true)) {
                            finishHim(null, e);
                        }
                    }
                }
            }, monitorIds.size());
            for (String monitorId : monitorIds) {
                deleteAlertingMonitor(monitorId, request.getRefreshPolicy(),
                        deletesListener);
            }
        }

        private void deleteDetectorFromConfig(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
            deleteDetector(detectorId, refreshPolicy,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteResponse response) {

                            indexTemplateManager.deleteAllUnusedTemplates(new ActionListener<Void>() {
                                @Override
                                public void onResponse(Void unused) {
                                    onOperation(response);
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error("Error deleting unused templates: " + e.getMessage());
                                    onOperation(response);
                                }
                            });

                        }
                        @Override
                        public void onFailure(Exception t) {
                            onFailures(t);
                        }
                    });
        }

        private void onOperation(DeleteResponse response) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(response.getId(), null);
            }
        }

        private void onFailures(Exception t) {
            log.error(String.format(Locale.ROOT, "Failed to delete detector"));
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(String detectorId, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    log.error(String.format(Locale.ROOT, "Failed to delete detector %s",detectorId), t);
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new DeleteDetectorResponse(detectorId, NO_VERSION, RestStatus.NO_CONTENT);
                }
            }));
        }

        private boolean isOnlyMonitorOrIndexMissingExceptionThrownByGroupedActionListener(
                Exception ex,
                String detectorId
        ) {
            // grouped action listener listens on mutliple listeners but throws only one exception. If multiple
            // listeners fail the other exceptions are added as suppressed exceptions to the first failure.
            int len = ex.getSuppressed().length;
            for (int i = 0; i <= len; i++) {
                Throwable e = i == len ? ex : ex.getSuppressed()[i];
                if (e.getMessage().matches("(.*)Monitor(.*) is not found(.*)")
                                || e.getMessage().contains(
                                        "Configured indices are not found: [.opendistro-alerting-config]")
                ) {
                    log.error(
                            String.format(Locale.ROOT, "Monitor or jobs index already deleted." +
                                    " Proceeding with detector %s deletion", detectorId),
                            e);
                } else {
                    return false;
                }
            }
            return true;
        }
    }
}