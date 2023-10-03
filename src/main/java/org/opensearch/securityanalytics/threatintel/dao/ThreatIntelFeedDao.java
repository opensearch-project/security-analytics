/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.dao;

import static org.opensearch.securityanalytics.threatintel.jobscheduler.Datasource.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import lombok.NonNull;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.Requests;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatintel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatintel.common.ThreatIntelSettings;

import org.opensearch.securityanalytics.threatintel.common.StashedThreadContext;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

/**
 * Data access object  for threat intel feed data
 */
public class ThreatIntelFeedDao {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final String IP_RANGE_FIELD_NAME = "_cidr";
    private static final String DATA_FIELD_NAME = "_data";
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
    private final Client client;

    public ThreatIntelFeedDao(final ClusterService clusterService, final Client client) {
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.client = client;
    }

    /**
     * Create an index for TIF data
     *
     * Index setting start with single shard, zero replica, no refresh interval, and hidden.
     * Once the TIF data is indexed, do refresh and force merge.
     * Then, change the index setting to expand replica to all nodes, and read only allow delete.
     * See {@link #freezeIndex}
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
                () -> client.admin().indices().create(createIndexRequest).actionGet(clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT))
        );
    }

    private void freezeIndex(final String indexName) {
        TimeValue timeout = clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT);
        StashedThreadContext.run(client, () -> {
            client.admin().indices().prepareForceMerge(indexName).setMaxNumSegments(1).execute().actionGet(timeout);
            client.admin().indices().prepareRefresh(indexName).execute().actionGet(timeout);
            client.admin()
                    .indices()
                    .prepareUpdateSettings(indexName)
                    .setSettings(INDEX_SETTING_TO_FREEZE)
                    .execute()
                    .actionGet(clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT));
        });
    }

    /**
     * Generate XContentBuilder representing datasource database index mapping
     *
     * {
     *     "dynamic": false,
     *     "properties": {
     *         "_cidr": {
     *             "type": "ip_range",
     *             "doc_values": false
     *         }
     *     }
     * }
     *
     * @return String representing datasource database index mapping
     */
    private String getIndexMapping() {
        try {
            try (InputStream is = DatasourceDao.class.getResourceAsStream("/mappings/threat_intel_feed_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception", e);
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }

    /**
     * Create CSVParser of a threat intel feed
     *
     * @param manifest Datasource manifest
     * @return CSVParser for threat intel feed
     */
    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    public CSVParser getDatabaseReader(final DatasourceManifest manifest) {
        SpecialPermission.check();
        return AccessController.doPrivileged((PrivilegedAction<CSVParser>) () -> {
            try {
                URL zipUrl = new URL(manifest.getUrl());
                return internalGetDatabaseReader(manifest, zipUrl.openConnection());
            } catch (IOException e) {
                log.error("Exception: failed to read threat intel feed data from {}",manifest.getUrl(), e);
                throw new OpenSearchException("failed to read threat intel feed data from {}", manifest.getUrl(), e);
            }
        });
    }

    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    protected CSVParser internalGetDatabaseReader(final DatasourceManifest manifest, final URLConnection connection) throws IOException {
//        connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
        ZipInputStream zipIn = new ZipInputStream(connection.getInputStream());
        ZipEntry zipEntry = zipIn.getNextEntry();
        while (zipEntry != null) {
            if (zipEntry.getName().equalsIgnoreCase(manifest.getDbName()) == false) {
                zipEntry = zipIn.getNextEntry();
                continue;
            }
            return new CSVParser(new BufferedReader(new InputStreamReader(zipIn)), CSVFormat.RFC4180);
        }
        throw new IllegalArgumentException(
                String.format(Locale.ROOT, "database file [%s] does not exist in the zip file [%s]", manifest.getDbName(), manifest.getUrl())
        );
    }

    /**
     * Create a document to ingest in datasource database index
     *
     * It assumes the first field as ip_range. The rest is added under data field.
     *
     * Document example
     * {
     *   "_cidr":"1.0.0.1/25",
     *   "_data":{
     *       "country": "USA",
     *       "city": "Seattle",
     *       "location":"13.23,42.12"
     *   }
     * }
     *
     * @param fields a list of field name
     * @param values a list of values
     * @return Document in json string format
     * @throws IOException the exception
     */
    public XContentBuilder createDocument(final String[] fields, final String[] values) throws IOException {
        if (fields.length != values.length) {
            throw new OpenSearchException("header[{}] and record[{}] length does not match", fields, values);
        }
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder.startObject();
        builder.field(IP_RANGE_FIELD_NAME, values[0]);
        builder.startObject(DATA_FIELD_NAME);
        for (int i = 1; i < fields.length; i++) {
            if (Strings.isBlank(values[i])) {
                continue;
            }
            builder.field(fields[i], values[i]);
        }
        builder.endObject();
        builder.endObject();
        builder.close();
        return builder;
    }

    /**
     * Query a given index using a given ip address to get TIF data
     *
     * @param indexName index
     * @param ip ip address
     * @return TIF data
     */
    public Map<String, Object> getTIFData(final String indexName, final String ip) {
        SearchResponse response = StashedThreadContext.run(
                client,
                () -> client.prepareSearch(indexName)
                        .setSize(1)
                        .setQuery(QueryBuilders.termQuery(IP_RANGE_FIELD_NAME, ip))
                        .setPreference(Preference.LOCAL.type())
                        .setRequestCache(true)
                        .get(clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT))
        );

        if (response.getHits().getHits().length == 0) {
            return Collections.emptyMap();
        } else {
            return (Map<String, Object>) XContentHelper.convertToMap(response.getHits().getAt(0).getSourceRef(), false, XContentType.JSON)
                    .v2()
                    .get(DATA_FIELD_NAME);
        }
    }

    /**
     * Puts TIF data from CSVRecord iterator into a given index in bulk
     *
     * @param indexName Index name to puts the TIF data
     * @param fields Field name matching with data in CSVRecord in order
     * @param iterator TIF data to insert
     * @param renewLock Runnable to renew lock
     */
    public void putTIFData(
            @NonNull final String indexName,
            @NonNull final String[] fields,
            @NonNull final Iterator<CSVRecord> iterator,
            @NonNull final Runnable renewLock
    ) throws IOException {
        TimeValue timeout = clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT);
        Integer batchSize = clusterSettings.get(ThreatIntelSettings.BATCH_SIZE);
        final BulkRequest bulkRequest = new BulkRequest();
        Queue<DocWriteRequest> requests = new LinkedList<>();
        for (int i = 0; i < batchSize; i++) {
            requests.add(Requests.indexRequest(indexName));
        }
        while (iterator.hasNext()) {
            CSVRecord record = iterator.next();
            XContentBuilder document = createDocument(fields, record.values());
            IndexRequest indexRequest = (IndexRequest) requests.poll();
            indexRequest.source(document);
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
                        .actionGet(clusterSettings.get(ThreatIntelSettings.THREAT_INTEL_TIMEOUT))
        );

        if (response.isAcknowledged() == false) {
            throw new OpenSearchException("failed to delete data[{}] in datasource", String.join(",", indices));
        }
    }
}
