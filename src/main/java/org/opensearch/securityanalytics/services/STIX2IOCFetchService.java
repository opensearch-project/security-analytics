/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.action.TestS3ConnectionResponse;
import org.opensearch.securityanalytics.commons.connector.Connector;
import org.opensearch.securityanalytics.commons.connector.S3Connector;
import org.opensearch.securityanalytics.commons.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.commons.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsAssumeRoleCredentialsProviderFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsClientFactory;
import org.opensearch.securityanalytics.commons.connector.model.InputCodecSchema;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.model.FeedConfiguration;
import org.opensearch.securityanalytics.commons.model.IOCSchema;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.commons.model.UpdateType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobParameterService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.sts.model.StsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * IOC Service implements operations that interact with retrieving IOCs from data sources,
 * parsing them into threat intel data models (i.e., [IOC]), and ingesting them to system indexes.
 */
public class STIX2IOCFetchService {
    private final Logger log = LogManager.getLogger(STIX2IOCFetchService.class);
    private final String ENDPOINT_CONFIG_PATH = "/threatIntelFeed/internalAuthEndpoint.txt";

    private Client client;
    private ClusterService clusterService;
    private STIX2IOCConnectorFactory connectorFactory;
    private S3ClientFactory s3ClientFactory;

    // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
    private Integer batchSize;
    private String internalAuthEndpoint = "";

    public STIX2IOCFetchService(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        this.internalAuthEndpoint = getEndpoint();

        StsAssumeRoleCredentialsProviderFactory factory =
                new StsAssumeRoleCredentialsProviderFactory(new StsClientFactory());
        s3ClientFactory = new S3ClientFactory(factory, internalAuthEndpoint);
        connectorFactory = new STIX2IOCConnectorFactory(new InputCodecFactory(), s3ClientFactory);
        batchSize = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
    }

    /**
     * Method takes in and calls method to rollover and bulk index a list of STIX2IOCs
     * @param saTifSourceConfig
     * @param stix2IOCList
     * @param listener
     */
    public void onlyIndexIocs(SATIFSourceConfig saTifSourceConfig,
                              List<STIX2IOC> stix2IOCList,
                              ActionListener<STIX2IOCFetchResponse> listener)
    {
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        try {
            feedStore.indexIocs(stix2IOCList);
        } catch (Exception e) {
            log.error("Failed to index IOCs from source config", e);
            listener.onFailure(e);
        }
    }
    public void downloadAndIndexIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchResponse> listener) {
        S3ConnectorConfig s3ConnectorConfig = constructS3ConnectorConfig(saTifSourceConfig);
        Connector<STIX2> s3Connector = constructS3Connector(s3ConnectorConfig);
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        STIX2IOCConsumer consumer = new STIX2IOCConsumer(batchSize, feedStore, UpdateType.REPLACE);

        try {
            s3Connector.load(consumer);
        } catch (Exception e) {
            log.error("Failed to download IOCs.", e);
            listener.onFailure(e);
            return;
        }

        // TODO consider passing listener into the flush IOC function
        try {
            consumer.flushIOCs();
        } catch (Exception e) {
            log.error("Failed to flush IOCs queue.", e);
            listener.onFailure(e);
        }
    }

    public void testS3Connection(S3ConnectorConfig s3ConnectorConfig, ActionListener<TestS3ConnectionResponse> listener) {
        if (internalAuthEndpoint.isEmpty()) {
            testS3ClientConnection(s3ConnectorConfig, listener);
        } else {
            testAmazonS3Connection(s3ConnectorConfig, listener);
        }
    }

    private void testS3ClientConnection(S3ConnectorConfig s3ConnectorConfig, ActionListener<TestS3ConnectionResponse> listener) {
        try {
            S3Connector<STIX2> connector = (S3Connector<STIX2>) constructS3Connector(s3ConnectorConfig);
            HeadObjectResponse response = connector.testS3Connection(s3ConnectorConfig);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(response.sdkHttpResponse().statusCode()), ""));
        } catch (NoSuchKeyException noSuchKeyException) {
            log.warn("S3Client connection test failed with NoSuchKeyException: ", noSuchKeyException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(noSuchKeyException.statusCode()), noSuchKeyException.awsErrorDetails().errorMessage()));
        } catch (S3Exception s3Exception) {
            log.warn("S3Client connection test failed with S3Exception: ", s3Exception);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(s3Exception.statusCode()), "Resource not found."));
        } catch (StsException stsException) {
            log.warn("S3Client connection test failed with StsException: ", stsException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(stsException.statusCode()), stsException.awsErrorDetails().errorMessage()));
        } catch (SdkException sdkException ) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            log.warn("S3Client connection test failed with SdkException: ", sdkException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.FORBIDDEN, "Resource not found."));
        } catch (Exception e) {
            log.warn("S3Client connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }

    }

    private void testAmazonS3Connection(S3ConnectorConfig s3ConnectorConfig, ActionListener<TestS3ConnectionResponse> listener) {
        try {
            S3Connector<STIX2> connector = (S3Connector<STIX2>) constructS3Connector(s3ConnectorConfig);
            boolean response = connector.testAmazonS3Connection(s3ConnectorConfig);
            listener.onResponse(new TestS3ConnectionResponse(response ? RestStatus.OK : RestStatus.FORBIDDEN, ""));
        } catch (AmazonServiceException e) {
            log.warn("AmazonS3 connection test failed with AmazonServiceException: ", e);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(e.getStatusCode()), e.getErrorMessage()));
        } catch (SdkClientException e) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            log.warn("AmazonS3 connection test failed with SdkClientException: ", e);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.FORBIDDEN, "Resource not found."));
        } catch (Exception e) {
            log.warn("AmazonS3 connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }

    private Connector<STIX2> constructS3Connector(S3ConnectorConfig s3ConnectorConfig) {
        FeedConfiguration feedConfiguration = new FeedConfiguration(IOCSchema.STIX2, InputCodecSchema.ND_JSON, s3ConnectorConfig);
        if (internalAuthEndpoint.isEmpty()) {
            return constructS3ClientConnector(feedConfiguration);
        } else {
            return constructAmazonS3Connector(feedConfiguration);
        }
    }

    private Connector<STIX2> constructS3ClientConnector(FeedConfiguration feedConfiguration) {
        return connectorFactory.doCreate(feedConfiguration);
    }

    private Connector<STIX2> constructAmazonS3Connector(FeedConfiguration feedConfiguration) {
        List<String> clusterTuple = List.of(clusterService.getClusterName().value().split(":"));
        return connectorFactory.createAmazonS3Connector(feedConfiguration, clusterTuple);
    }

    private S3ConnectorConfig constructS3ConnectorConfig(SATIFSourceConfig saTifSourceConfig) {
        S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                ((S3Source) saTifSourceConfig.getSource()).getBucketName(),
                ((S3Source) saTifSourceConfig.getSource()).getObjectKey(),
                ((S3Source) saTifSourceConfig.getSource()).getRegion(),
                ((S3Source) saTifSourceConfig.getSource()).getRoleArn()
        );
        validateS3ConnectorConfig(s3ConnectorConfig);
        return s3ConnectorConfig;
    }

    private void validateS3ConnectorConfig(S3ConnectorConfig s3ConnectorConfig) {
        if (s3ConnectorConfig.getRoleArn() == null || s3ConnectorConfig.getRoleArn().isEmpty()) {
            throw new IllegalArgumentException("Role arn is required.");
        }

        if (s3ConnectorConfig.getRegion() == null || s3ConnectorConfig.getRegion().isEmpty()) {
            throw new IllegalArgumentException("Region is required.");
        }
    }

    private String getEndpoint() {
        try {
            try (InputStream is = TIFJobParameterService.class.getResourceAsStream(ENDPOINT_CONFIG_PATH)) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (Exception e) {
            log.debug(String.format("Resource file [%s] doesn't exist.", ENDPOINT_CONFIG_PATH));
        }
        return "";
    }

    public static class STIX2IOCFetchResponse extends ActionResponse implements ToXContentObject {
        public static String IOCS_FIELD = "iocs";
        public static String TOTAL_FIELD = "total";
        public static String DURATION_FIELD = "took";
        private List<STIX2IOCDto> iocs = new ArrayList<>();
        private long duration; // In milliseconds

        public STIX2IOCFetchResponse(List<STIX2IOC> iocs, long duration) {
            super();
            iocs.forEach(ioc -> this.iocs.add(new STIX2IOCDto(ioc)));
            this.duration = duration;
        }

        public STIX2IOCFetchResponse(StreamInput sin) throws IOException {
            this(sin.readList(STIX2IOC::new), sin.readLong());
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeList(iocs);
            out.writeLong(duration);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject()
                    .field(TOTAL_FIELD, iocs.size())
                    .field(DURATION_FIELD, duration)
                    .endObject();
        }

        public List<STIX2IOCDto> getIocs() {
            return iocs;
        }
    }
}
