package org.opensearch.securityanalytics.threatIntel;

import org.apache.commons.csv.CSVRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.Requests;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.findings.FindingsService;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.threatIntel.common.Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

/**
 * Service to handle CRUD operations on Threat Intel Feed Data
 */
public class ThreatIntelFeedDataService {
    private static final Logger log = LogManager.getLogger(FindingsService.class);

    private final ClusterState state;
    private final Client client;
    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private static final Map<String, Object> INDEX_SETTING_TO_CREATE = Map.of(
            "index.number_of_shards",
            1,
            "index.number_of_replicas",
            0,
            "index.refresh_interval",
            -1,
            "index.hidden",
            true
    );
    private static final Map<String, Object> INDEX_SETTING_TO_FREEZE = Map.of(
            "index.auto_expand_replicas",
            "0-all",
            "index.blocks.write",
            true
    );
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;

    public ThreatIntelFeedDataService(
            ClusterState state,
            ClusterService clusterService,
            Client client,
            IndexNameExpressionResolver indexNameExpressionResolver,
            NamedXContentRegistry xContentRegistry) {
        this.state = state;
        this.client = client;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

    private final NamedXContentRegistry xContentRegistry;

    public void getThreatIntelFeedData(
            String iocType,
            ActionListener<List<ThreatIntelFeedData>> listener
    ) {
        String tifdIndex = IndexUtils.getNewIndexByCreationDate(
                this.state,
                this.indexNameExpressionResolver,
                ".opensearch-sap-threatintel*" //name?
        );
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.boolQuery().filter(QueryBuilders.termQuery("ioc_type", iocType)));
        SearchRequest searchRequest = new SearchRequest(tifdIndex);
        searchRequest.source().size(9999); //TODO: convert to scroll
        searchRequest.source(sourceBuilder);
        client.search(searchRequest, ActionListener.wrap(r -> listener.onResponse(getTifdList(r)), e -> {
            log.error(String.format(
                    "Failed to fetch threat intel feed data from system index %s", tifdIndex), e);
            listener.onFailure(e);
        }));
    }

    private List<ThreatIntelFeedData> getTifdList(SearchResponse searchResponse) {
        List<ThreatIntelFeedData> list = new ArrayList<>();
        if (searchResponse.getHits().getHits().length != 0) {
            Arrays.stream(searchResponse.getHits().getHits()).forEach(hit -> {
                try {
                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                            xContentRegistry,
                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                    );
                    list.add(ThreatIntelFeedData.parse(xcp, hit.getId(), hit.getVersion()));
                } catch (Exception e) {
                    log.error(() -> new ParameterizedMessage(
                                    "Failed to parse Threat intel feed data doc from hit {}", hit),
                            e
                    );
                }

            });
        }
        return list;
    }




    /**
     * Create an index for a threat intel feed
     *
     * Index setting start with single shard, zero replica, no refresh interval, and hidden.
     * Once the threat intel feed is indexed, do refresh and force merge.
     * Then, change the index setting to expand replica to all nodes, and read only allow delete.
     *
     * @param indexName index name
     */
    public void createIndexIfNotExists(final String indexName) {
        if (clusterService.state().metadata().hasIndex(indexName) == true) {
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName).settings(INDEX_SETTING_TO_CREATE)
                .mapping(getIndexMapping());
        StashedThreadContext.run(
                client,
                () -> client.admin().indices().create(createIndexRequest).actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT))
        );
    }
    private String getIndexMapping() {
        try {
            try (InputStream is = DatasourceDao.class.getResourceAsStream("/mappings/threat_intel_feed_mapping.json")) { // TODO: check Datasource dao and this mapping
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception when getting the threat intel index mapping", e);
            throw new SecurityAnalyticsException("Runtime exception when getting the threat intel index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Puts threat intel feed from CSVRecord iterator into a given index in bulk
     *
     * @param indexName Index name to puts the TIF data
     * @param fields Field name matching with data in CSVRecord in order
     * @param iterator TIF data to insert
     * @param renewLock Runnable to renew lock
     */
    public void saveThreatIntelFeedDataCSV(
            final String indexName,
            final String[] fields,
            final Iterator<CSVRecord> iterator,
            final Runnable renewLock,
            final DatasourceManifest manifest
    ) throws IOException {
        if (indexName == null || fields == null || iterator == null || renewLock == null){
            throw new IllegalArgumentException("Parameters cannot be null, failed to save threat intel feed data");
        }

        TimeValue timeout = clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT);
        Integer batchSize = clusterSettings.get(SecurityAnalyticsSettings.BATCH_SIZE);
        final BulkRequest bulkRequest = new BulkRequest();
        Queue<DocWriteRequest> requests = new LinkedList<>();
        for (int i = 0; i < batchSize; i++) {
            requests.add(Requests.indexRequest(indexName));
        }

        while (iterator.hasNext()) {
            CSVRecord record = iterator.next();
            String iocType = "";
            if (manifest.getContainedIocs().get(0) == "ip") { //TODO: dynamically get the type
                iocType = "ip";
            }
            Integer colNum = Integer.parseInt(manifest.getIocCol());
            String iocValue = record.values()[colNum];
            String feedId = manifest.getFeedId();
            Instant timestamp = Instant.now();

            ThreatIntelFeedData threatIntelFeedData = new ThreatIntelFeedData(iocType, iocValue, feedId, timestamp);
            XContentBuilder tifData = threatIntelFeedData.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
            IndexRequest indexRequest = (IndexRequest) requests.poll();
            indexRequest.source(tifData);
            indexRequest.id(record.get(0));
            bulkRequest.add(indexRequest);
            if (iterator.hasNext() == false || bulkRequest.requests().size() == batchSize) {
                BulkResponse response = StashedThreadContext.run(client, () -> client.bulk(bulkRequest).actionGet(timeout));
                if (response.hasFailures()) {
                    throw new OpenSearchException(
                            "error occurred while ingesting threat intel feed data in {} with an error {}",
                            indexName,
                            response.buildFailureMessage()
                    );
                }
                requests.addAll(bulkRequest.requests());
                bulkRequest.requests().clear();
            }
            renewLock.run();
        }
        freezeIndex(indexName);
    }

    private void freezeIndex(final String indexName) {
        TimeValue timeout = clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT);
        StashedThreadContext.run(client, () -> {
            client.admin().indices().prepareForceMerge(indexName).setMaxNumSegments(1).execute().actionGet(timeout);
            client.admin().indices().prepareRefresh(indexName).execute().actionGet(timeout);
            client.admin()
                    .indices()
                    .prepareUpdateSettings(indexName)
                    .setSettings(INDEX_SETTING_TO_FREEZE)
                    .execute()
                    .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));
        });
    }

    public void deleteThreatIntelDataIndex(final String index) {
        deleteThreatIntelDataIndex(Arrays.asList(index));
    }

    public void deleteThreatIntelDataIndex(final List<String> indices) {
        if (indices == null || indices.isEmpty()) {
            return;
        }

        Optional<String> invalidIndex = indices.stream()
                .filter(index -> index.startsWith(THREAT_INTEL_DATA_INDEX_NAME_PREFIX) == false)
                .findAny();
        if (invalidIndex.isPresent()) {
            throw new OpenSearchException(
                    "the index[{}] is not threat intel data index which should start with {}",
                    invalidIndex.get(),
                    THREAT_INTEL_DATA_INDEX_NAME_PREFIX
            );
        }

        AcknowledgedResponse response = StashedThreadContext.run(
                client,
                () -> client.admin()
                        .indices()
                        .prepareDelete(indices.toArray(new String[0]))
                        .setIndicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED_HIDDEN)
                        .execute()
                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT))
        );

        if (response.isAcknowledged() == false) {
            throw new OpenSearchException("failed to delete data[{}] in datasource", String.join(",", indices));
        }
    }

}
