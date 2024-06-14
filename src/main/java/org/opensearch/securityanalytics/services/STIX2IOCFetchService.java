/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.commons.connector.S3Connector;
import org.opensearch.securityanalytics.commons.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.commons.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsAssumeRoleCredentialsProviderFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsClientFactory;
import org.opensearch.securityanalytics.commons.connector.model.InputCodecSchema;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.factory.ConnectorFactory;
import org.opensearch.securityanalytics.commons.model.FeedConfiguration;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.IOCSchema;
import org.opensearch.securityanalytics.commons.model.UpdateType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;

import java.io.IOException;
import java.time.Instant;
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
    private ConnectorFactory connectorFactory;
    private S3ClientFactory s3ClientFactory;

    // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
    private Integer batchSize;

    public STIX2IOCFetchService(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;

        StsAssumeRoleCredentialsProviderFactory factory =
                new StsAssumeRoleCredentialsProviderFactory(new StsClientFactory());
        s3ClientFactory = new S3ClientFactory(factory);
        connectorFactory = new ConnectorFactory(new InputCodecFactory(), s3ClientFactory);
        batchSize = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
    }

    public void fetchIocs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchResponse> listener) {
        Instant startTime = Instant.now();

        S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                ((S3Source) saTifSourceConfig.getSource()).getBucketName(),
                ((S3Source) saTifSourceConfig.getSource()).getObjectKey(),
                ((S3Source) saTifSourceConfig.getSource()).getRegion(),
                ((S3Source) saTifSourceConfig.getSource()).getRoleArn()
        );
        validateS3ConnectorConfig(s3ConnectorConfig);

        FeedConfiguration feedConfiguration = new FeedConfiguration(IOCSchema.STIX2, InputCodecSchema.ND_JSON, s3ConnectorConfig);
        S3Connector s3Connector = (S3Connector<IOC>) connectorFactory.doCreate(feedConfiguration);
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        STIX2IOCConsumer consumer = new STIX2IOCConsumer(batchSize, feedStore, UpdateType.REPLACE);

        // TODO hurneyt add start and end time; return in response
        s3Connector.load(consumer);
        consumer.flushIOCs();
    }

    public void validateS3ConnectorConfig(S3ConnectorConfig s3ConnectorConfig) {
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
        public static String RESPONSE_STATUS_FIELD = "status";
        private List<STIX2IOCDto> iocs = new ArrayList<>();

        public STIX2IOCFetchResponse(List<STIX2IOC> iocs) {
            super();
            iocs.forEach(ioc -> {
//                log.info("hurneyt ioc == null = {}", ioc == null);
                this.iocs.add(new STIX2IOCDto(ioc));
            });
        }

        public STIX2IOCFetchResponse(StreamInput sin) throws IOException {
            this(sin.readList(STIX2IOC::new));
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeList(iocs);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            return builder.startObject()
                    // TODO hurneyt include IOCs in response?
//                    .field(IOCS_FIELD, this.iocs)
                    .field(TOTAL_FIELD, iocs.size())
                    .endObject();
        }

        public List<STIX2IOCDto> getIocs() {
            return iocs;
        }
    }
}
