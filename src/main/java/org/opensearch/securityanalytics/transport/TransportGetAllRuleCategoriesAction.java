/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesRequest;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesResponse;
import org.opensearch.securityanalytics.model.RuleCategory;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetAllRuleCategoriesAction extends HandledTransportAction<GetAllRuleCategoriesRequest, GetAllRuleCategoriesResponse> {

    private final ThreadPool threadPool;

    @Inject
    public TransportGetAllRuleCategoriesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            GetAllRuleCategoriesAction getAllRuleCategoriesAction,
            ClusterService clusterService,
            ThreadPool threadPool
    ) {
        super(getAllRuleCategoriesAction.NAME, transportService, actionFilters, GetAllRuleCategoriesRequest::new);
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, GetAllRuleCategoriesRequest request, ActionListener<GetAllRuleCategoriesResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();
        actionListener.onResponse(new GetAllRuleCategoriesResponse(RuleCategory.ALL_RULE_CATEGORIES));
    }
}