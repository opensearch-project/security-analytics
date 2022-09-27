/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionListener;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.settings.Settings;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.BytesRestResponse;

import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;

import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;

import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;

import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.List;


import static org.opensearch.rest.RestStatus.OK;

public class TransportGetDetectorAction extends HandledTransportAction<GetDetectorRequest, GetDetectorResponse> {

    private final Client client;

    private static final Logger log = LogManager.getLogger(TransportGetDetectorAction.class);


    @Inject
    public TransportGetDetectorAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            GetDetectorAction getDetectorAction
    ) {
        super(getDetectorAction.NAME, transportService, actionFilters, GetDetectorRequest::new);
        this.client = client;
    }

    private final static XContentParser parser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;
    }

    private final static NamedXContentRegistry xContentRegistry() {
        return new NamedXContentRegistry(
                List.of(
                        Detector.XCONTENT_REGISTRY
                )
        );
    }

    @Override
    protected void doExecute(Task task, GetDetectorRequest request, ActionListener<GetDetectorResponse> actionListener) {

        GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, request.getDetectorId());

        client.get(getRequest, new ActionListener<>() {
            @Override
            public void onResponse(GetResponse getDetectorResponse) {
                Detector detector = null;
                try {
                    log.error(getDetectorResponse.getSourceAsString());
                    detector = Detector.parse(parser(getDetectorResponse.getSourceAsString()),getDetectorResponse.getId(), getDetectorResponse.getVersion() );
                    actionListener.onResponse(new GetDetectorResponse(detector.getId(), detector.getVersion(), OK, detector));
                } catch (Exception e) {
                    onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

}