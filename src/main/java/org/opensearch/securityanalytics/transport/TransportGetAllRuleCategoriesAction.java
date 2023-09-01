/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.stream.Collectors;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesRequest;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesResponse;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.RuleCategory;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetAllRuleCategoriesAction extends HandledTransportAction<GetAllRuleCategoriesRequest, GetAllRuleCategoriesResponse> implements SecureTransportAction {

    private final ThreadPool threadPool;
    private final LogTypeService logTypeService;

    @Inject
    public TransportGetAllRuleCategoriesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetAllRuleCategoriesAction getAllRuleCategoriesAction,
            LogTypeService logTypeService,
            ThreadPool threadPool
    ) {
        super(getAllRuleCategoriesAction.NAME, transportService, actionFilters, GetAllRuleCategoriesRequest::new);
        this.threadPool = threadPool;
        this.logTypeService = logTypeService;
    }

    @Override
    protected void doExecute(Task task, GetAllRuleCategoriesRequest request, ActionListener<GetAllRuleCategoriesResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();
        logTypeService.getAllLogTypesMetadata(ActionListener.wrap(logTypes -> {
            actionListener.onResponse(
                new GetAllRuleCategoriesResponse(
                    logTypes.stream().map(logType -> new RuleCategory(logType, logType)).collect(Collectors.toList())
                )
            );
        }, e -> actionListener.onFailure(SecurityAnalyticsException.wrap(e))));

    }
}
