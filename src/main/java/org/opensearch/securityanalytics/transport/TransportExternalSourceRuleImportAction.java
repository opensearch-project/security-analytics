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
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportAction;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportRequest;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportResponse;
import org.opensearch.securityanalytics.rules.externalsourcing.ExternalRuleSourcer;
import org.opensearch.securityanalytics.rules.externalsourcing.ExternalRuleSourcerManager;
import org.opensearch.securityanalytics.rules.externalsourcing.RuleImportOptions;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportExternalSourceRuleImportAction extends HandledTransportAction<ExternalSourceRuleImportRequest, ExternalSourceRuleImportResponse> {
    private ExternalRuleSourcerManager externalRuleSourcerManager;
    private ClusterService clusterService;

    private final ThreadPool threadPool;


    @Inject
    public TransportExternalSourceRuleImportAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            ExternalRuleSourcerManager externalRuleSourcerManager,
            ClusterService clusterService
    ) {
        super(ExternalSourceRuleImportAction.NAME, transportService, actionFilters, ExternalSourceRuleImportRequest::new);
        this.clusterService = clusterService;
        this.externalRuleSourcerManager = externalRuleSourcerManager;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, ExternalSourceRuleImportRequest request, ActionListener<ExternalSourceRuleImportResponse> actionListener) {
        this.threadPool.getThreadContext().stashContext();

        ExternalRuleSourcer externalRuleSourcer = externalRuleSourcerManager.getSourcerById(request.getSourceId());

        if (externalRuleSourcer == null) {
            actionListener.onFailure(
                    SecurityAnalyticsException.wrap(new IllegalArgumentException("Sourcer with provided id not found"))
            );
        }
        externalRuleSourcer.importRules(RuleImportOptions.OVERWRITE_MODIFIED_IGNORE_DELETED, actionListener);
    }
}