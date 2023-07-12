/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.List;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.ValidateRulesAction;
import org.opensearch.securityanalytics.action.ValidateRulesRequest;
import org.opensearch.securityanalytics.action.ValidateRulesResponse;
import org.opensearch.securityanalytics.util.RuleValidator;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportValidateRulesAction extends HandledTransportAction<ValidateRulesRequest, ValidateRulesResponse> {

    private final RuleValidator ruleValidator;
    private final ClusterService clusterService;

    @Inject
    public TransportValidateRulesAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ClusterService clusterService,
            Client client,
            NamedXContentRegistry namedXContentRegistry
    ) {
        super(ValidateRulesAction.NAME, transportService, actionFilters, ValidateRulesRequest::new);
        this.clusterService = clusterService;
        this.ruleValidator = new RuleValidator(client, namedXContentRegistry);
    }

    @Override
    protected void doExecute(Task task, ValidateRulesRequest request, ActionListener<ValidateRulesResponse> actionListener) {
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