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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.TestS3ConnectionAction;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;
import org.opensearch.securityanalytics.action.TestS3ConnectionResponse;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.sts.model.StsException;

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
//            HeadObjectResponse response = stix2IOCFetchService.testS3Connection(request.constructS3ConnectorConfig());
//            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(response.sdkHttpResponse().statusCode()), ""));
            Boolean response = stix2IOCFetchService.testAmazonS3Connection(request.constructS3ConnectorConfig());
            listener.onResponse(new TestS3ConnectionResponse(response.booleanValue() ? RestStatus.OK : RestStatus.FORBIDDEN, ""));
        } catch (NoSuchKeyException noSuchKeyException) {
            log.warn("S3 connection test failed with NoSuchKeyException: ", noSuchKeyException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(noSuchKeyException.statusCode()), noSuchKeyException.awsErrorDetails().errorMessage()));
        } catch (S3Exception s3Exception) {
            log.warn("S3 connection test failed with S3Exception: ", s3Exception);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(s3Exception.statusCode()), "Resource not found."));
        } catch (StsException stsException) {
            log.warn("S3 connection test failed with StsException: ", stsException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(stsException.statusCode()), stsException.awsErrorDetails().errorMessage()));
        } catch (SdkException sdkException ) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            log.warn("S3 connection test failed with SdkException: ", sdkException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.BAD_REQUEST, "Resource not found."));
        } catch (Exception e) {
            log.warn("S3 connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }
}
