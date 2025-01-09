/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.fasterxml.jackson.databind.RuntimeJsonMappingException;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.bulk.BulkRequest;
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
import org.opensearch.securityanalytics.commons.connector.exceptions.ConnectorParsingException;
import org.opensearch.securityanalytics.commons.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.commons.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsAssumeRoleCredentialsProviderFactory;
import org.opensearch.securityanalytics.commons.connector.factory.StsClientFactory;
import org.opensearch.securityanalytics.commons.connector.model.InputCodecSchema;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.model.FeedConfiguration;
import org.opensearch.securityanalytics.commons.model.IOCSchema;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.commons.model.UpdateType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.model.UrlDownloadSource;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelFeedParser;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.service.ThreatIntelFeedDataService.isValidIp;

/**
 * IOC Service implements operations that interact with retrieving IOCs from data sources,
 * parsing them into threat intel data models (i.e., [IOC]), and ingesting them to system indexes.
 */
public class STIX2IOCFetchService {
    private final Logger log = LogManager.getLogger(STIX2IOCFetchService.class);
    private final String ENDPOINT_CONFIG_PATH = "/threatIntelFeed/internalAuthEndpoint.txt";

    public final String REGION_REGEX = "^.{1,20}$";
    public final String ROLE_ARN_REGEX = "^arn:aws:iam::\\d{12}:role/[\\w+=,.@-]{1,64}$";

    private Client client;
    private ClusterService clusterService;
    private STIX2IOCConnectorFactory connectorFactory;
    private S3ClientFactory s3ClientFactory;

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
     *
     * @param saTifSourceConfig
     * @param stix2IOCList
     * @param listener
     */
    public void onlyIndexIocs(SATIFSourceConfig saTifSourceConfig,
                              List<STIX2IOC> stix2IOCList,
                              ActionListener<STIX2IOCFetchResponse> listener) {
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        Instant startTime = Instant.now();
        Instant endTime;
        Exception exception = null;
        RestStatus restStatus = null;
        try {
            log.info("Started IOC index step at {}.", startTime);
            feedStore.indexIocs(stix2IOCList);
        } catch (IllegalArgumentException e) {
            exception = e;
            restStatus = RestStatus.BAD_REQUEST;
        } catch (OpenSearchException e) {
            exception = e;
            restStatus = e.status();
        } catch (Exception e) {
            exception = e;
            restStatus = RestStatus.INTERNAL_SERVER_ERROR;
        }
        endTime = Instant.now();
        long took = Duration.between(startTime, endTime).toMillis();

        if (exception != null && restStatus != null) {
            String errorText = getErrorText(saTifSourceConfig, "index", took);
            log.error(errorText, exception);
            listener.onFailure(new SecurityAnalyticsException(errorText, restStatus, exception));
        } else {
            log.info("IOC index step took {} milliseconds.", took);
        }
    }

    public void downloadAndIndexIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchResponse> listener) {
        S3ConnectorConfig s3ConnectorConfig;
        try {
            s3ConnectorConfig = constructS3ConnectorConfig(saTifSourceConfig);
        } catch (SecurityAnalyticsException e) {
            listener.onFailure(e);
            return;
        }

        Connector<STIX2> s3Connector = constructS3Connector(s3ConnectorConfig);
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        STIX2IOCConsumer consumer = new STIX2IOCConsumer(batchSize, feedStore, UpdateType.REPLACE);

        Instant startTime = Instant.now();
        Instant endTime;
        Exception exception = null;
        RestStatus restStatus = null;
        try {
            log.info("Started IOC download step at {}.", startTime);
            s3Connector.load(consumer);
        } catch (IllegalArgumentException | ConnectorParsingException | RuntimeJsonMappingException e) {
            exception = e;
            restStatus = RestStatus.BAD_REQUEST;
        } catch (StsException | S3Exception e) {
            exception = e;
            restStatus = RestStatus.fromCode(e.statusCode());
        } catch (AmazonServiceException e) {
            exception = e;
            restStatus = RestStatus.fromCode(e.getStatusCode());
        } catch (SdkException | SdkClientException e) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            exception = e;
            restStatus = RestStatus.FORBIDDEN;
        } catch (Exception e) {
            exception = e;
            restStatus = RestStatus.INTERNAL_SERVER_ERROR;
        }
        endTime = Instant.now();
        long took = Duration.between(startTime, endTime).toMillis();

        if (exception != null && restStatus != null) {
            String errorText = getErrorText(saTifSourceConfig, "download", took);
            log.error(errorText, exception);
            listener.onFailure(new SecurityAnalyticsException(errorText, restStatus, exception));
            return;
        } else {
            log.info("IOC download step took {} milliseconds.", took);
        }

        startTime = Instant.now();
        try {
            log.info("Started IOC flush at {}.", startTime);
            consumer.flushIOCs();
        } catch (IllegalArgumentException e) {
            exception = e;
            restStatus = RestStatus.BAD_REQUEST;
        } catch (OpenSearchException e) {
            exception = e;
            restStatus = e.status();
        } catch (Exception e) {
            exception = e;
            restStatus = RestStatus.INTERNAL_SERVER_ERROR;
        }
        endTime = Instant.now();
        took = Duration.between(startTime, endTime).toMillis();

        if (exception != null && restStatus != null) {
            String errorText = getErrorText(saTifSourceConfig, "index", took);
            log.error(errorText, exception);
            listener.onFailure(new SecurityAnalyticsException(errorText, restStatus, exception));
        } else {
            log.info("IOC flush step took {} milliseconds.", took);
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
            log.error("S3Client connection test failed with NoSuchKeyException: ", noSuchKeyException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(noSuchKeyException.statusCode()), noSuchKeyException.awsErrorDetails().errorMessage()));
        } catch (S3Exception s3Exception) {
            log.error("S3Client connection test failed with S3Exception: ", s3Exception);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(s3Exception.statusCode()), "Resource not found."));
        } catch (StsException stsException) {
            log.error("S3Client connection test failed with StsException: ", stsException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(stsException.statusCode()), stsException.awsErrorDetails().errorMessage()));
        } catch (SdkException sdkException) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            log.error("S3Client connection test failed with SdkException: ", sdkException);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.FORBIDDEN, "Resource not found."));
        } catch (Exception e) {
            log.error("S3Client connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }

    private void testAmazonS3Connection(S3ConnectorConfig s3ConnectorConfig, ActionListener<TestS3ConnectionResponse> listener) {
        try {
            S3Connector<STIX2> connector = (S3Connector<STIX2>) constructS3Connector(s3ConnectorConfig);
            boolean response = connector.testAmazonS3Connection(s3ConnectorConfig);
            listener.onResponse(new TestS3ConnectionResponse(response ? RestStatus.OK : RestStatus.FORBIDDEN, ""));
        } catch (AmazonServiceException e) {
            log.error("AmazonS3 connection test failed with AmazonServiceException: ", e);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.fromCode(e.getStatusCode()), e.getErrorMessage()));
        } catch (SdkClientException e) {
            // SdkException is a RunTimeException that doesn't have a status code.
            // Logging the full exception, and providing generic response as output.
            log.error("AmazonS3 connection test failed with SdkClientException: ", e);
            listener.onResponse(new TestS3ConnectionResponse(RestStatus.FORBIDDEN, "Resource not found."));
        } catch (Exception e) {
            log.error("AmazonS3 connection test failed with error: ", e);
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
        if (s3ConnectorConfig.getRoleArn() == null || !s3ConnectorConfig.getRoleArn().matches(ROLE_ARN_REGEX)) {
            throw new SecurityAnalyticsException("Role arn is empty or malformed.", RestStatus.BAD_REQUEST, new IllegalArgumentException());
        }

        if (s3ConnectorConfig.getRegion() == null || !s3ConnectorConfig.getRegion().matches(REGION_REGEX)) {
            throw new SecurityAnalyticsException("Region is empty or malformed.", RestStatus.BAD_REQUEST, new IllegalArgumentException());
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

    public void downloadFromUrlAndIndexIOCs(SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchResponse> listener) {
        UrlDownloadSource source = (UrlDownloadSource) saTifSourceConfig.getSource();
        switch (source.getFeedFormat()) { // todo add check to stop user from creating url type config from rest api. only internal allowed
            case "csv":
                try (CSVParser reader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(source.getUrl())) {
                    CSVParser noHeaderReader = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(source.getUrl());
                    boolean notFound = true;

                    while (notFound) {
                        CSVRecord hasHeaderRecord = reader.iterator().next();

                        //if we want to skip this line and keep iterating
                        if ((hasHeaderRecord.values().length == 1 && "".equals(hasHeaderRecord.values()[0])) || hasHeaderRecord.get(0).charAt(0) == '#' || hasHeaderRecord.get(0).charAt(0) == ' ') {
                            noHeaderReader.iterator().next();
                        } else { // we found the first line that contains information
                            notFound = false;
                        }
                    }
                    if (source.hasCsvHeader()) {
                        parseAndSaveThreatIntelFeedDataCSV(reader.iterator(), saTifSourceConfig, listener);
                    } else {
                        parseAndSaveThreatIntelFeedDataCSV(noHeaderReader.iterator(), saTifSourceConfig, listener);
                    }
                } catch (Exception e) {
                    log.error("Failed to download the IoCs in CSV format for source " + saTifSourceConfig.getId());
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                    return;
                }
                break;
            default:
                log.error("unsupported feed format for url download:" + source.getFeedFormat());
                listener.onFailure(SecurityAnalyticsException.wrap(new UnsupportedOperationException("unsupported feed format for url download:" + source.getFeedFormat())));
        }
    }

    private void parseAndSaveThreatIntelFeedDataCSV(Iterator<CSVRecord> iterator, SATIFSourceConfig saTifSourceConfig, ActionListener<STIX2IOCFetchResponse> listener) throws IOException {
        List<BulkRequest> bulkRequestList = new ArrayList<>();

        UrlDownloadSource source = (UrlDownloadSource) saTifSourceConfig.getSource();
        List<STIX2IOC> iocs = new ArrayList<>();
        while (iterator.hasNext()) {
            CSVRecord record = iterator.next();
            String iocType = saTifSourceConfig.getIocTypes().stream().findFirst().orElse(null);
            Integer colNum = source.getCsvIocValueColumnNo();
            String iocValue = record.values()[colNum].split(" ")[0];
            if (iocType.equalsIgnoreCase(IOCType.IPV4_TYPE) && !isValidIp(iocValue)) {
                log.info("Invalid IP address, skipping this ioc record: {}", iocValue);
                continue;
            }
            Instant now = Instant.now();
            STIX2IOC stix2IOC = new STIX2IOC(
                    UUID.randomUUID().toString(),
                    UUID.randomUUID().toString(),
                    iocType,
                    iocValue,
                    "high",
                    now,
                    now,
                    "",
                    Collections.emptyList(),
                    "",
                    saTifSourceConfig.getId(),
                    saTifSourceConfig.getName(),
                    STIX2IOC.NO_VERSION
            );
            iocs.add(stix2IOC);
        }
        STIX2IOCFeedStore feedStore = new STIX2IOCFeedStore(client, clusterService, saTifSourceConfig, listener);
        feedStore.indexIocs(iocs);
    }

    /**
     * Helper function for generating error message text.
     * @param saTifSourceConfig The config for which IOCs are being downloaded/indexed.
     * @param action The action that was being taken when the error occurred; e.g., "download", or "index".
     * @param duration The amount of time, in milliseconds, it took for the action to fail.
     * @return The error message text.
     */
    private String getErrorText(SATIFSourceConfig saTifSourceConfig, String action, long duration) {
        return String.format(
                "Failed to %s IOCs from source config '%s' with ID %s after %s milliseconds: ",
                action,
                saTifSourceConfig.getName(),
                saTifSourceConfig.getId(),
                duration
        );
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
