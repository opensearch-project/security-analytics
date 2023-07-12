/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.apache.lucene.search.TotalHits;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchResponse;

import org.opensearch.action.search.SearchResponseSections;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.commons.authuser.User;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.settings.Settings;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.search.profile.SearchProfileShardResults;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.securityanalytics.action.SearchDetectorAction;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.threadpool.ThreadPool;

import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;


import java.util.Collections;
import java.util.Locale;

import static org.opensearch.rest.RestStatus.OK;
import static org.opensearch.securityanalytics.util.DetectorUtils.getEmptySearchResponse;

public class TransportSearchDetectorAction extends HandledTransportAction<SearchDetectorRequest, SearchResponse> implements SecureTransportAction {

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final DetectorIndices detectorIndices;

    private final Settings settings;

    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportSearchDetectorAction.class);


    @Inject
    public TransportSearchDetectorAction(TransportService transportService, ClusterService clusterService, DetectorIndices detectorIndices, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, Settings settings, Client client) {
        super(SearchDetectorAction.NAME, transportService, actionFilters, SearchDetectorRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
        this.detectorIndices = detectorIndices;
        this.clusterService = clusterService;
        this.threadPool = this.detectorIndices.getThreadPool();
        this.settings = settings;

        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, SearchDetectorRequest searchDetectorRequest, ActionListener<SearchResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        if (doFilterForUser(user, this.filterByEnabled)) {
            // security is enabled and filterby is enabled
            log.info("Filtering result by: {}", user.getBackendRoles());
            addFilter(user, searchDetectorRequest.searchRequest().source(), "detector.user.backend_roles.keyword");
        }

        this.threadPool.getThreadContext().stashContext();
        if (!detectorIndices.detectorIndexExists()) {
            actionListener.onResponse(getEmptySearchResponse());
            return;
        }
        client.search(searchDetectorRequest.searchRequest(), new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse response) {
                    actionListener.onResponse(response);
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