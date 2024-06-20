/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.UpdateAction;
import org.opensearch.securityanalytics.commons.store.FeedStore;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class STIX2IOCFeedStore implements FeedStore {
    public static final String IOC_INDEX_NAME_BASE = ".opensearch-sap-iocs";
    public static final String IOC_ALL_INDEX_PATTERN = IOC_INDEX_NAME_BASE + "-*";
    public static final String IOC_FEED_ID_PLACEHOLDER = "FEED_ID";
    public static final String IOC_INDEX_NAME_TEMPLATE = IOC_INDEX_NAME_BASE + "-" + IOC_FEED_ID_PLACEHOLDER;

    // TODO hurneyt implement history indexes + rollover logic
    public static final String IOC_HISTORY_WRITE_INDEX_ALIAS = IOC_INDEX_NAME_TEMPLATE + "-history-write";
    public static final String IOC_HISTORY_INDEX_PATTERN = "<." + IOC_INDEX_NAME_BASE + "-history-{now/d{yyyy.MM.dd.hh.mm.ss|UTC}}-1>";

    private final Logger log = LogManager.getLogger(STIX2IOCFeedStore.class);
    Instant startTime = Instant.now();

    private Client client;
    private ClusterService clusterService;
    private SATIFSourceConfig saTifSourceConfig;

    // TODO hurneyt FetchIocsActionResponse is just a placeholder response type for now
    private ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> baseListener;

    // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
    private Integer batchSize;

    public STIX2IOCFeedStore(
            Client client,
            ClusterService clusterService,
            SATIFSourceConfig saTifSourceConfig,
            ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> listener) {
        super();
        this.client = client;
        this.clusterService = clusterService;
        this.saTifSourceConfig = saTifSourceConfig;
        this.baseListener = listener;
        batchSize = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
    }

    @Override
    public void storeIOCs(Map<IOC, UpdateAction> actionToIOCs) {
        Map<UpdateAction, List<STIX2IOC>> iocsSortedByAction = new HashMap<>();
        actionToIOCs.forEach((key, value) -> {
            if (key.getClass() != STIX2IOC.class) {
                throw new IllegalArgumentException("Only supports STIX2-formatted IOCs.");
            } else {
                iocsSortedByAction.putIfAbsent(value, new ArrayList<>());
                iocsSortedByAction.get(value).add((STIX2IOC) key);
            }
        });

        for (Map.Entry<UpdateAction, List<STIX2IOC>> entry : iocsSortedByAction.entrySet()) {
            switch (entry.getKey()) {
                case DELETE:
                    // TODO hurneyt consider whether DELETE actions should be handled elsewhere
                    break;
                case UPSERT:
                    try {
                        indexIocs(entry.getValue());
                    } catch (IOException e) {
                        baseListener.onFailure(new RuntimeException(e));
                    }
                    break;
                default:
                    baseListener.onFailure(new IllegalArgumentException("Unsupported action."));
            }
        }
    }

    public void indexIocs(List<STIX2IOC> iocs) throws IOException {
        // TODO @jowg, there seems to be a bug in SATIFSourceConfigManagementService.
        //  downloadAndSaveIOCs is called before indexTIFSourceConfig, which means the config doesn't have an ID to use when creating the system index to store IOCs.
        //  Testing using SaTifSourceConfigDto.getName() instead of .getId() for now.
        String feedIndexName = initFeedIndex(saTifSourceConfig.getName());

        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();

        for (STIX2IOC ioc : iocs) {
            IndexRequest indexRequest = new IndexRequest(feedIndexName)
                    .opType(DocWriteRequest.OpType.INDEX)
                    .source(ioc.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
            }
        }
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        bulkRequestList.add(bulkRequest);

        GroupedActionListener<BulkResponse> bulkResponseListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
            int idx = 0;
            for (BulkResponse response : bulkResponses) {
                BulkRequest request = bulkRequestList.get(idx);
                if (response.hasFailures()) {
                    throw new OpenSearchException(
                            "Error occurred while ingesting IOCs to {} with an error {}",
                            StringUtils.join(request.getIndices()),
                            response.buildFailureMessage()
                    );
                }
                idx++;
            }

            long duration = Duration.between(startTime, Instant.now()).toMillis();
            STIX2IOCFetchService.STIX2IOCFetchResponse output = new STIX2IOCFetchService.STIX2IOCFetchResponse(iocs, duration);
            baseListener.onResponse(output);
        }, baseListener::onFailure), bulkRequestList.size());

        for (BulkRequest req : bulkRequestList) {
            try {
                StashedThreadContext.run(client, () -> client.bulk(req, bulkResponseListener));
            } catch (OpenSearchException e) {
                log.error("Failed to save IOCs.", e);
                baseListener.onFailure(e);
            }
        }
    }

    /**
     * Checks whether the [IOC_INDEX_NAME_BASE]-related index exists.
     * @param index The index to evaluate.
     * @return TRUE if the index is an IOC-related system index, and exists; else returns FALSE.
     */
    public boolean feedIndexExists(String index) {
        return index.startsWith(IOC_INDEX_NAME_BASE) && this.clusterService.state().routingTable().hasIndex(index);
    }

    public static String getFeedConfigIndexName(String feedSourceConfigId) {
        return IOC_INDEX_NAME_TEMPLATE.replace(IOC_FEED_ID_PLACEHOLDER, feedSourceConfigId.toLowerCase(Locale.ROOT));
    }

    // TODO hurneyt change ActionResponse to more specific response once it's available
    public String initFeedIndex(String feedSourceConfigId) {
        String feedIndexName = getFeedConfigIndexName(feedSourceConfigId);
        if (!feedIndexExists(feedIndexName)) {
            var indexRequest = new CreateIndexRequest(feedIndexName)
                    .mapping(iocIndexMapping())
                    .settings(Settings.builder().put("index.hidden", true).build());

            ActionListener<CreateIndexResponse> createListener = new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse createIndexResponse) {
                    log.info("Created system index {}", feedIndexName);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to create system index {}", feedIndexName);
                    baseListener.onFailure(e);
                }
            };

            client.admin().indices().create(indexRequest, createListener);
        }
        return feedIndexName;
    }

    public String iocIndexMapping() {
        String iocMappingFile = "mappings/stix2_ioc_mapping.json";
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(iocMappingFile)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load stix2_ioc_mapping.json file [" + iocMappingFile + "]", e);
        }
    }

    public SATIFSourceConfig getSaTifSourceConfig() {
        return saTifSourceConfig;
    }
}
