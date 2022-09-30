/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

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
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.BytesRestResponse;

import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;

import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;

import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;

import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.List;


import static org.opensearch.rest.RestStatus.OK;

public class TransportGetDetectorAction extends HandledTransportAction<GetDetectorRequest, GetDetectorResponse> {

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private static final Logger log = LogManager.getLogger(TransportGetDetectorAction.class);


    @Inject
    public TransportGetDetectorAction(TransportService transportService, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, Client client) {
        super(GetDetectorAction.NAME, transportService, actionFilters, GetDetectorRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, GetDetectorRequest request, ActionListener<GetDetectorResponse> actionListener) {

        GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, request.getDetectorId())
                .version(request.getVersion());

        client.get(getRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetResponse response) {
                try {
                    if (!response.isExists()) {
                        actionListener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Detector not found.", RestStatus.NOT_FOUND)));
                        return;
                    }
                    Detector detector = null;
                    if (!response.isSourceEmpty()) {
                        XContentParser xcp = XContentHelper.createParser(
                                xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                response.getSourceAsBytesRef(), XContentType.JSON
                        );
                        detector = Detector.docParse(xcp, response.getId(), response.getVersion());
                    }
                    assert detector != null;
                    actionListener.onResponse(new GetDetectorResponse(detector.getId(), detector.getVersion(), OK, detector));
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

}