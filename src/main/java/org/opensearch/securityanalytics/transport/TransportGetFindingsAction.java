/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetFindingsRequest;
import org.opensearch.securityanalytics.action.GetFindingsResponse;
import org.opensearch.securityanalytics.findings.FindingsService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;


import static org.opensearch.rest.RestStatus.OK;

public class TransportGetFindingsAction extends HandledTransportAction<GetFindingsRequest, GetFindingsResponse> {

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final FindingsService findingsService;

    private static final Logger log = LogManager.getLogger(TransportGetFindingsAction.class);


    @Inject
    public TransportGetFindingsAction(TransportService transportService, ActionFilters actionFilters, FindingsService findingsService, NamedXContentRegistry xContentRegistry, Client client) {
        super(GetFindingsAction.NAME, transportService, actionFilters, GetFindingsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
        this.findingsService = findingsService;
    }

    @Override
    protected void doExecute(Task task, GetFindingsRequest request, ActionListener<GetFindingsResponse> actionListener) {
        findingsService.getFindingsByDetectorId(request.getDetectorId(), actionListener);
    }

}