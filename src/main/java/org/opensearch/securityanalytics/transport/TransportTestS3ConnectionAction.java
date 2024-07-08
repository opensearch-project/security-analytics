/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.action.TestS3ConnectionAction;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;
import org.opensearch.securityanalytics.action.TestS3ConnectionResponse;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportTestS3ConnectionAction extends HandledTransportAction<TestS3ConnectionRequest, TestS3ConnectionResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportTestS3ConnectionAction.class);

    private final STIX2IOCFetchService stix2IOCFetchService;

    @Inject
    public TransportTestS3ConnectionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            STIX2IOCFetchService stix2IOCFetchService
            ) {
        super(TestS3ConnectionAction.NAME, transportService, actionFilters, TestS3ConnectionRequest::new);
        this.stix2IOCFetchService = stix2IOCFetchService;
    }

    @Override
    protected void doExecute(Task task, TestS3ConnectionRequest request, ActionListener<TestS3ConnectionResponse> listener) {
        try {
            stix2IOCFetchService.testS3Connection(request.constructS3ConnectorConfig(), listener);
        } catch (Exception e) {
            log.warn("S3 connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }
}
