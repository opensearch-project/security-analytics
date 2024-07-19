/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.List;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.ValidateRulesAction;
import org.opensearch.securityanalytics.action.ValidateRulesRequest;
import org.opensearch.securityanalytics.action.ValidateRulesResponse;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.RuleValidator;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportValidateRulesAction extends HandledTransportAction<ValidateRulesRequest, ValidateRulesResponse> implements SecureTransportAction{

    private final RuleValidator ruleValidator;
    private final ClusterService clusterService;
    private final Settings settings;
    private final ThreadPool threadPool;
    private volatile Boolean filterByEnabled;

    @Inject
    public TransportValidateRulesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ClusterService clusterService,
            final ThreadPool threadPool,
            Settings settings,
            Client client,
            NamedXContentRegistry namedXContentRegistry
    ) {
        super(ValidateRulesAction.NAME, transportService, actionFilters, ValidateRulesRequest::new);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.ruleValidator = new RuleValidator(client, namedXContentRegistry);
    }

    @Override
    protected void doExecute(Task task, ValidateRulesRequest request, ActionListener<ValidateRulesResponse> actionListener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        this.threadPool.getThreadContext().stashContext();

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
        StepListener<List<String>> validateRulesResponseListener = new StepListener();
        validateRulesResponseListener.whenComplete(validateRulesResponse -> {
            actionListener.onResponse(new ValidateRulesResponse(validateRulesResponse));
        }, actionListener::onFailure);
        ruleValidator.validateCustomRules(request.getRules(), request.getIndexName(), validateRulesResponseListener);
    }
}