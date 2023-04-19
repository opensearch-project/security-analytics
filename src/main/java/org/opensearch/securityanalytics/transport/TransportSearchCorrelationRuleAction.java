/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.TotalHits;
import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.commons.notifications.action.SendNotificationRequest;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleAction;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleRequest;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportSearchCorrelationRuleAction extends HandledTransportAction<SearchCorrelationRuleRequest, SearchResponse> {

    private static final Logger log = LogManager.getLogger(TransportSearchCorrelationRuleAction.class);

    private final Client client;

    private final CorrelationRuleIndices correlationRuleIndices;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private static final SearchResponse EMPTY_SEARCH_RESPONSE = new SearchResponse(
        new InternalSearchResponse(
            new SearchHits(new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0f),
            null,
            null,
            null,
            false,
            null,
            1
        ),
        null,
        0,
        0,
        0,
        0,
        ShardSearchFailure.EMPTY_ARRAY,
        SearchResponse.Clusters.EMPTY
    );


    @Inject
    public TransportSearchCorrelationRuleAction(
        TransportService transportService,
        Client client,
        ActionFilters actionFilters,
        ClusterService clusterService,
        ThreadPool threadPool,
        CorrelationRuleIndices correlationRuleIndices
    ) {
        super(SearchCorrelationRuleAction.NAME, transportService, actionFilters, SearchCorrelationRuleRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.correlationRuleIndices = correlationRuleIndices;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(Task task, SearchCorrelationRuleRequest request, ActionListener<SearchResponse> listener) {
        this.threadPool.getThreadContext().stashContext();

        client.search(
            request.getSearchRequest(),
            new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    listener.onResponse(response);
                }

                @Override
                public void onFailure(Exception e) {
                    if (e instanceof IndexNotFoundException) {
                        listener.onResponse(EMPTY_SEARCH_RESPONSE);
                    } else {
                        listener.onFailure(SecurityAnalyticsException.wrap(e));
                    }
                }
            }
        );
    }

}
