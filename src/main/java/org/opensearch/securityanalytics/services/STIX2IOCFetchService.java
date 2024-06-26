/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
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
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * IOC Service implements operations that interact with retrieving IOCs from data sources,
 * parsing them into threat intel data models (i.e., [IOC]), and ingesting them to system indexes.
 */
public class STIX2IOCFetchService {
    private final Logger log = LogManager.getLogger(STIX2IOCFetchService.class);

    private Client client;
    private ClusterService clusterService;
    private STIX2IOCConnectorFactory connectorFactory;
    private S3ClientFactory s3ClientFactory;

    // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
    private Integer batchSize;

    public STIX2IOCFetchService(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;

        StsAssumeRoleCredentialsProviderFactory factory =
                new StsAssumeRoleCredentialsProviderFactory(new StsClientFactory());
        s3ClientFactory = new S3ClientFactory(factory);
        connectorFactory = new STIX2IOCConnectorFactory(new InputCodecFactory(), s3ClientFactory);
        batchSize = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
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
        }

        // TODO consider passing listener into the flush IOC function
        try {
            consumer.flushIOCs();
        } catch (Exception e) {
            log.error("Failed to flush IOCs queue.", e);
            listener.onFailure(e);
        }
    }

    public HeadObjectResponse testS3Connection(S3ConnectorConfig s3ConnectorConfig) {
        S3Connector<STIX2> connector = (S3Connector<STIX2>) constructS3Connector(s3ConnectorConfig);
        return connector.testS3Connection(s3ConnectorConfig);
    }

    public Boolean testAmazonS3Connection(S3ConnectorConfig s3ConnectorConfig) {
        S3Connector<STIX2> connector = (S3Connector<STIX2>) constructS3Connector(s3ConnectorConfig);
        return connector.testAmazonS3Connection(s3ConnectorConfig);
    }

    private Connector<STIX2> constructS3Connector(S3ConnectorConfig s3ConnectorConfig) {
        FeedConfiguration feedConfiguration = new FeedConfiguration(IOCSchema.STIX2, InputCodecSchema.ND_JSON, s3ConnectorConfig);
        // TODO hurneyt hard coded for testing purposes only
        log.info("hurneyt cluster name = {}", clusterService.getClusterName().value());
        List<String> clusterTuple = List.of(clusterService.getClusterName().value().split(":"));
//                List.of("540654354201", "test-2130-threat-int-hurneyt");
        return connectorFactory.createAmazonS3Connector(feedConfiguration, clusterTuple);
//        return connectorFactory.doCreate(feedConfiguration);
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
                    // TODO hurneyt include IOCs in response?
//                    .field(IOCS_FIELD, this.iocs)
                    .field(TOTAL_FIELD, iocs.size())
                    .field(DURATION_FIELD, duration)
                    .endObject();
        }

        public List<STIX2IOCDto> getIocs() {
            return iocs;
        }
    }
}
