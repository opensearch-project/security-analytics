/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchResponse;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.rest.RestStatus;
import org.opensearch.common.xcontent.NamedXContentRegistry;

import org.opensearch.securityanalytics.action.SearchDetectorAction;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;

import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;


import static org.opensearch.rest.RestStatus.OK;

public class TransportSearchDetectorAction extends HandledTransportAction<SearchDetectorRequest, SearchResponse> {

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private static final Logger log = LogManager.getLogger(TransportSearchDetectorAction.class);


    @Inject
    public TransportSearchDetectorAction(TransportService transportService, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, Client client) {
        super(SearchDetectorAction.NAME, transportService, actionFilters, SearchDetectorRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, SearchDetectorRequest searchDetectorRequest, ActionListener<SearchResponse> actionListener) {

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

}