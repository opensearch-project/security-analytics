/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import com.amazonaws.services.s3.AmazonS3;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.commons.connector.Connector;
import org.opensearch.securityanalytics.commons.connector.S3Connector;
import org.opensearch.securityanalytics.commons.connector.codec.InputCodec;
import org.opensearch.securityanalytics.commons.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.commons.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.factory.UnaryParameterCachingFactory;
import org.opensearch.securityanalytics.commons.model.FeedConfiguration;
import org.opensearch.securityanalytics.commons.model.FeedLocation;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import software.amazon.awssdk.services.s3.S3Client;

import java.util.List;

public class STIX2IOCConnectorFactory extends UnaryParameterCachingFactory<FeedConfiguration, Connector<STIX2>> {
    private static final Logger logger = LogManager.getLogger(STIX2IOCConnectorFactory.class);
    private final InputCodecFactory inputCodecFactory;
    private final S3ClientFactory s3ClientFactory;

    public STIX2IOCConnectorFactory(final InputCodecFactory inputCodecFactory, final S3ClientFactory s3ClientFactory) {
        this.inputCodecFactory = inputCodecFactory;
        this.s3ClientFactory = s3ClientFactory;
    }

    protected Connector<STIX2> doCreate(FeedConfiguration feedConfiguration) {
        final FeedLocation feedLocation = FeedLocation.fromFeedConfiguration(feedConfiguration);
        logger.debug("FeedLocation: {}", feedLocation);
        switch (feedLocation) {
            case S3:
                return createS3Connector(feedConfiguration, null);
            default:
                throw new IllegalArgumentException("Unsupported feedLocation: " + feedLocation);
        }
    }

    protected Connector<STIX2> doCreate(FeedConfiguration feedConfiguration, SATIFSourceConfig satifSourceConfig) {
        final FeedLocation feedLocation = FeedLocation.fromFeedConfiguration(feedConfiguration);
        logger.debug("FeedLocation: {}", feedLocation);
        switch (feedLocation) {
            case S3:
                return createS3Connector(feedConfiguration, satifSourceConfig);
            default:
                throw new IllegalArgumentException("Unsupported feedLocation: " + feedLocation);
        }
    }

    private S3Connector<STIX2> createS3Connector(final FeedConfiguration feedConfiguration, SATIFSourceConfig satifSourceConfig) {
        final InputCodec inputCodec = getInputCodec(feedConfiguration, satifSourceConfig);
        final S3ConnectorConfig s3ConnectorConfig = feedConfiguration.getS3ConnectorConfig();
        final S3Client s3Client = s3ClientFactory.create(s3ConnectorConfig.getRoleArn(), s3ConnectorConfig.getRegion());
        return new S3Connector<>(s3ConnectorConfig, s3Client, inputCodec);
    }

    private InputCodec getInputCodec(FeedConfiguration feedConfiguration, SATIFSourceConfig satifSourceConfig) {
        final InputCodec inputCodec;
        if (satifSourceConfig != null && satifSourceConfig.getIocSchema() != null) {
            logger.info("Parsing custom schema JSON from S3 for threat intel source [{}]", satifSourceConfig.getName());
            inputCodec = new JsonPathAwareInputCodec(satifSourceConfig);
        } else {
            inputCodec = inputCodecFactory.create(feedConfiguration.getIocSchema().getModelClass(), feedConfiguration.getInputCodecSchema());
        }
        return inputCodec;
    }

    public S3Connector<STIX2> createAmazonS3Connector(final FeedConfiguration feedConfiguration, List<String> clusterTuple, SATIFSourceConfig satifSourceConfig) {
        final InputCodec inputCodec = getInputCodec(feedConfiguration, satifSourceConfig);
        final S3ConnectorConfig s3ConnectorConfig = feedConfiguration.getS3ConnectorConfig();
        final AmazonS3 s3Client = s3ClientFactory.createAmazonS3(s3ConnectorConfig.getRoleArn(), s3ConnectorConfig.getRegion(), clusterTuple);
        return new S3Connector<>(s3ConnectorConfig, s3Client, inputCodec);
    }
}
