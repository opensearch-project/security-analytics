/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.Map;

public class TransportUpdateIndexMappingsAction extends HandledTransportAction<UpdateIndexMappingsRequest, AcknowledgedResponse> {

    private MapperService mapperService;
    private ClusterService clusterService;

    private final ThreadPool threadPool;
    private final Client client;

    @Inject
    public TransportUpdateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            UpdateIndexMappingsAction updateIndexMappingsAction,
            MapperService mapperService,
            ClusterService clusterService,
            Client client
    ) {
        super(UpdateIndexMappingsAction.NAME, transportService, actionFilters, UpdateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, UpdateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        // Verify caller has indices:admin/mapping/put on the target index before elevating privileges.
        // Issues a no-op PutMappingRequest (empty properties) as the caller — the security plugin
        // checks the permission naturally without stashContext, so unauthorized users get 403.
        PutMappingRequest putMappingRequest = new PutMappingRequest(request.getIndexName())
                .source(Map.of("properties", Map.of()));
        client.admin().indices().putMapping(putMappingRequest, ActionListener.wrap(
                putMappingResponse -> {
                    this.threadPool.getThreadContext().stashContext();
                    try {
                        IndexMetadata index = clusterService.state().metadata().index(request.getIndexName());
                        if (index == null) {
                            actionListener.onFailure(
                                    SecurityAnalyticsException.wrap(
                                            new OpenSearchStatusException(
                                                    "Could not find index [" + request.getIndexName() + "]", RestStatus.NOT_FOUND
                                            )
                                    )
                            );
                            return;
                        }
                        mapperService.updateMappingAction(
                                request.getIndexName(),
                                request.getAlias(),
                                buildAliasJson(request.getField()),
                                actionListener)
                        ;
                    } catch (IOException e) {
                        actionListener.onFailure(e);
                    }
                },
                e -> {
                    if (isIndexNotFoundException(e)) {
                        actionListener.onFailure(
                                SecurityAnalyticsException.wrap(
                                        new OpenSearchStatusException(
                                                "Could not find index [" + request.getIndexName() + "]", RestStatus.NOT_FOUND
                                        )
                                )
                        );
                    } else {
                        actionListener.onFailure(e);
                    }
                }
        ));
    }

    private boolean isIndexNotFoundException(Exception e) {
        if (e instanceof IndexNotFoundException) {
            return true;
        }
        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof IndexNotFoundException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private String buildAliasJson(String fieldName) throws IOException {
        return "type=alias,path=" + fieldName;
    }
}
