/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.commons.authuser.User;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetRuleAction;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.action.GetRuleRequest;
import org.opensearch.securityanalytics.action.GetRuleResponse;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;


import static org.opensearch.core.rest.RestStatus.OK;

public class TransportGetRuleAction extends HandledTransportAction<GetRuleRequest, GetRuleResponse> implements SecureTransportAction {

    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final RuleIndices ruleIndices;
    private final ClusterService clusterService;
    private final Settings settings;
    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    @Inject
    public TransportGetRuleAction(TransportService transportService, ActionFilters actionFilters, RuleIndices ruleIndices, ClusterService clusterService, NamedXContentRegistry xContentRegistry, Client client, Settings settings) {
        super(GetRuleAction.NAME, transportService, actionFilters, GetRuleRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
        this.ruleIndices = ruleIndices;
        this.clusterService = clusterService;
        this.threadPool = this.ruleIndices.getThreadPool();
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetRuleRequest request, ActionListener<GetRuleResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        String index = Rule.CUSTOM_RULES_INDEX;
        if(request.isPrepackaged()) {
            index = Rule.PRE_PACKAGED_RULES_INDEX;
        }

        GetRequest getRequest = new GetRequest(index, request.getRuleId()).version(request.getVersion());
        client.get(getRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetResponse response) {
                try {
                    if (!response.isExists()) {
                        actionListener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Rule not found.", RestStatus.NOT_FOUND)));
                        return;
                    }
                    Rule rule = null;
                    if (!response.isSourceEmpty()) {
                        XContentParser xcp = XContentHelper.createParser(
                                xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                response.getSourceAsBytesRef(), XContentType.JSON
                        );
                        rule = Rule.docParse(xcp, response.getId(), response.getVersion());
                        assert rule != null;
                    }
                    actionListener.onResponse(new GetRuleResponse(rule.getId(), rule.getVersion(), OK, rule));
                } catch (IOException ex) {
                    actionListener.onFailure(ex);
                }
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}