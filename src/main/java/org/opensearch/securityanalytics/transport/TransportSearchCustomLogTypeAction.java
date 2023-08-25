/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import org.opensearch.core.action.ActionListener;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeAction;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeRequest;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportSearchCustomLogTypeAction extends HandledTransportAction<SearchCustomLogTypeRequest, SearchResponse> implements SecureTransportAction {

    private final Client client;

    private final Settings settings;

    private volatile Boolean filterByEnabled;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final LogTypeService logTypeService;

    @Inject
    public TransportSearchCustomLogTypeAction(
            TransportService transportService,
            ClusterService clusterService,
            ActionFilters actionFilters,
            ThreadPool threadPool,
            Settings settings,
            Client client,
            LogTypeService logTypeService
    ) {
        super(SearchCustomLogTypeAction.NAME, transportService, actionFilters, SearchCustomLogTypeRequest::new);
        this.client = client;
        this.settings = settings;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.logTypeService = logTypeService;

        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, SearchCustomLogTypeRequest request, ActionListener<SearchResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        if (doFilterForUser(user, this.filterByEnabled)) {
            // security is enabled and filterby is enabled
            log.info("Filtering result by: {}", user.getBackendRoles());
            addFilter(user, request.searchRequest().source(), "detector.user.backend_roles.keyword");
        }

        this.threadPool.getThreadContext().stashContext();
        logTypeService.searchLogTypes(request.searchRequest(), new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse response) {
                listener.onResponse(response);
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}