/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;

public class TransportUpdateIndexMappingsAction extends HandledTransportAction<UpdateIndexMappingsRequest, AcknowledgedResponse> implements SecureTransportAction{

    private MapperService mapperService;
    private ClusterService clusterService;
    private final ThreadPool threadPool;
    private final Settings settings;
    private volatile Boolean filterByEnabled;


    @Inject
    public TransportUpdateIndexMappingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            UpdateIndexMappingsAction updateIndexMappingsAction,
            MapperService mapperService,
            ClusterService clusterService,
            Settings settings
    ) {
        super(UpdateIndexMappingsAction.NAME, transportService, actionFilters, UpdateIndexMappingsRequest::new);
        this.clusterService = clusterService;
        this.mapperService = mapperService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
    }

    @Override
    protected void doExecute(Task task, UpdateIndexMappingsRequest request, ActionListener<AcknowledgedResponse> actionListener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
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
    }

    private String buildAliasJson(String fieldName) throws IOException {
        return "type=alias,path=" + fieldName;
    }
}