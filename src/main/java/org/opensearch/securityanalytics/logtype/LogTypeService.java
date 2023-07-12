/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.logtype;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.util.set.Sets;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.search.aggregations.bucket.terms.TermsAggregationBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.model.FieldMappingDoc;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import static org.opensearch.action.support.ActiveShardCount.ALL;
import static org.opensearch.securityanalytics.model.FieldMappingDoc.LOG_TYPES;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.DEFAULT_MAPPING_SCHEMA;


/**
 *
 * */
public class LogTypeService {

    private static final Logger logger = LogManager.getLogger(LogTypeService.class);

    public static final String LOG_TYPE_INDEX = ".opensearch-sap-log-types-config";

    public static final String LOG_TYPE_INDEX_MAPPING_FILE = "mappings/log_type_config_mapping.json";

    public static final String LOG_TYPE_MAPPING_VERSION_META_FIELD = "schema_version";

    public static final int LOG_TYPE_MAPPING_VERSION = 1; // must match version in log_type_config_mapping.json

    public static final int MAX_LOG_TYPE_COUNT = 100;

    private static volatile boolean isConfigIndexInitialized;

    private final Client client;

    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    private String defaultSchemaField;

    @Inject
    public LogTypeService(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry, BuiltinLogTypeLoader builtinLogTypeLoader) {
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
        this.builtinLogTypeLoader = builtinLogTypeLoader;

        this.defaultSchemaField = DEFAULT_MAPPING_SCHEMA.get(clusterService.getSettings());
        clusterService.getClusterSettings().addSettingsUpdateConsumer(
                DEFAULT_MAPPING_SCHEMA,
                newDefaultSchema -> this.defaultSchemaField = newDefaultSchema
        );
    }

    public void getAllLogTypes(ActionListener<List<String>> listener) {
        ensureConfigIndexIsInitialized(ActionListener.wrap(e -> {

            SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
            searchRequest.source(new SearchSourceBuilder().aggregation(
                new TermsAggregationBuilder("logTypes")
                    .field(LOG_TYPES)
                    .size(MAX_LOG_TYPE_COUNT)
            ));
            searchRequest.preference("_primary");
            client.search(
                searchRequest,
                ActionListener.delegateFailure(
                    listener,
                    (delegatedListener, searchResponse) -> {
                        List<String> logTypes = new ArrayList<>();
                        Terms termsAgg = searchResponse.getAggregations().get("logTypes");
                        for(Terms.Bucket bucket : termsAgg.getBuckets()) {
                            logTypes.add(bucket.getKeyAsString());
                        }
                        delegatedListener.onResponse(logTypes);
                    }
                )
            );
        }, listener::onFailure));
    }

    private void doIndexFieldMappings(List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        if (fieldMappingDocs.isEmpty()) {
            listener.onResponse(null);
        }
        getAllFieldMappings(ActionListener.wrap(existingFieldMappings -> {

            List<FieldMappingDoc> mergedFieldMappings = mergeFieldMappings(existingFieldMappings, fieldMappingDocs);

            BulkRequest bulkRequest = new BulkRequest();
            mergedFieldMappings.stream()
                    .filter(e -> e.isDirty())
                    .forEach(fieldMappingDoc -> {

                        IndexRequest indexRequest = new IndexRequest(LOG_TYPE_INDEX);
                        try {
                            indexRequest.id(fieldMappingDoc.getId() == null ? generateFieldMappingDocId(fieldMappingDoc) : fieldMappingDoc.getId());
                            indexRequest.source(fieldMappingDoc.toXContent(XContentFactory.jsonBuilder(), null));
                            indexRequest.opType(DocWriteRequest.OpType.INDEX);
                            bulkRequest.add(indexRequest);
                            bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                        } catch (IOException ex) {
                            logger.error("Failed converting FieldMappingDoc to XContent!", ex);
                        }
                    });
            // Index all fieldMapping docs
            logger.info("Indexing [" + bulkRequest.numberOfActions() + "] fieldMappingDocs");
            client.bulk(
                    bulkRequest,
                    ActionListener.delegateFailure(listener, (l, r) -> {
                        if (r.hasFailures()) {
                            logger.error("FieldMappingDoc Bulk Index had failures:\n ", r.buildFailureMessage());
                            listener.onFailure(new IllegalStateException(r.buildFailureMessage()));
                        } else {
                            logger.info("Loaded [" + r.getItems().length + "] field mapping docs successfully!");
                            listener.onResponse(null);
                        }
                    })
            );

        }, listener::onFailure));
    }

    private String generateFieldMappingDocId(FieldMappingDoc fieldMappingDoc) {
        String generatedId = fieldMappingDoc.getRawField() + "|";
        if (fieldMappingDoc.getSchemaFields().containsKey(defaultSchemaField)) {
            generatedId = generatedId + fieldMappingDoc.getSchemaFields().get(defaultSchemaField);
        }
        return generatedId;
    }

    public void indexFieldMappings(List<FieldMappingDoc> fieldMappingDocs, ActionListener<Void> listener) {
        ensureConfigIndexIsInitialized(ActionListener.wrap(e -> {
            doIndexFieldMappings(fieldMappingDocs, listener);
        }, listener::onFailure));
    }

    private List<FieldMappingDoc> mergeFieldMappings(List<FieldMappingDoc> existingFieldMappings, List<FieldMappingDoc> fieldMappingDocs) {
        // Insert new fieldMappings
        List<FieldMappingDoc> newFieldMappings = new ArrayList<>();
        fieldMappingDocs.forEach( newFieldMapping -> {
            Optional<FieldMappingDoc> foundFieldMappingDoc = existingFieldMappings
                    .stream()
                    .filter(
                        e -> e.getRawField().equals(newFieldMapping.getRawField()) && (
                            e.get(defaultSchemaField) != null && newFieldMapping.get(defaultSchemaField) != null &&
                            e.get(defaultSchemaField).equals(newFieldMapping.get(defaultSchemaField))
                        ) || (
                            e.get(defaultSchemaField) == null && newFieldMapping.get(defaultSchemaField) == null
                        )
                    )
                    .findFirst();
            if (foundFieldMappingDoc.isEmpty()) {
                newFieldMapping.setIsDirty(true);
                newFieldMappings.add(newFieldMapping);
            } else {
                // Merge new with existing by merging schema field mappings and log type arrays
                foundFieldMappingDoc.get().getSchemaFields().putAll(newFieldMapping.getSchemaFields());
                foundFieldMappingDoc.get().getLogTypes().addAll(newFieldMapping.getLogTypes());
                foundFieldMappingDoc.get().setIsDirty(true);
            }
        });
        existingFieldMappings.addAll(newFieldMappings);
        return existingFieldMappings;
    }

    public void getAllFieldMappings(ActionListener<List<FieldMappingDoc>> listener) {
        SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
        searchRequest.source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(10000));
        client.search(
            searchRequest,
            ActionListener.delegateFailure(
                listener,
                (delegatedListener, searchResponse) -> {
                    List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
                    for(SearchHit hit : searchResponse.getHits().getHits()) {
                        try {
                            fieldMappingDocs.add(FieldMappingDoc.parse(hit, xContentRegistry));
                        } catch (IOException e) {
                            logger.error("Failed parsing FieldMapping document", e);
                            delegatedListener.onFailure(e);
                            return;
                        }
                    }
                    delegatedListener.onResponse(fieldMappingDocs);
                }
            )
        );
    }

    public void getFieldMappingsByLogType(String logType, ActionListener<List<FieldMappingDoc>> listener) {
        ensureConfigIndexIsInitialized(ActionListener.wrap(() ->
            getFieldMappingsByLogTypes(List.of(logType), listener)
        ));
    }

    public void getFieldMappingsByLogTypes(List<String> logTypes, ActionListener<List<FieldMappingDoc>> listener) {
        SearchRequest searchRequest = new SearchRequest(LOG_TYPE_INDEX);
        searchRequest.source(new SearchSourceBuilder().query(
                QueryBuilders.termsQuery(LOG_TYPES, logTypes.toArray(new String[0])))
                .size(10000)
        );
        client.search(
                searchRequest,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, searchResponse) -> {
                            List<FieldMappingDoc> fieldMappingDocs = new ArrayList<>();
                            for(SearchHit hit : searchResponse.getHits().getHits()) {
                                try {
                                    fieldMappingDocs.add(FieldMappingDoc.parse(hit, xContentRegistry));
                                } catch (IOException e) {
                                    logger.error("Failed parsing FieldMapping document", e);
                                    delegatedListener.onFailure(e);
                                    return;
                                }
                            }
                            delegatedListener.onResponse(fieldMappingDocs);
                        }
                )
        );
    }
    /**
     * if isConfigIndexInitialized is false does following:
     * 1. Creates log type config index with proper mappings/settings
     * 2. Loads builtin log types into index
     * 3. sets isConfigIndexInitialized to true
     * */
    public void ensureConfigIndexIsInitialized(ActionListener<Void> listener) {

        ClusterState state = clusterService.state();

        if (state.routingTable().hasIndex(LOG_TYPE_INDEX) == false) {
            isConfigIndexInitialized = false;
            CreateIndexRequest createIndexRequest = new CreateIndexRequest();
            createIndexRequest.settings(logTypeIndexSettings());
            createIndexRequest.index(LOG_TYPE_INDEX);
            createIndexRequest.mapping(logTypeIndexMapping());
            createIndexRequest.cause("auto(sap-logtype api)");
            client.admin().indices().create(createIndexRequest, new ActionListener<>() {
                @Override
                public void onResponse(CreateIndexResponse result) {
                    loadBuiltinLogTypes(ActionListener.delegateFailure(
                            listener,
                            (delegatedListener, unused) -> {
                                isConfigIndexInitialized = true;
                                delegatedListener.onResponse(null);
                            })
                    );
                }

                @Override
                public void onFailure(Exception e) {
                    isConfigIndexInitialized = false;
                    if (ExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                        loadBuiltinLogTypes(ActionListener.delegateFailure(
                                listener,
                                (delegatedListener, unused) -> {
                                    isConfigIndexInitialized = true;
                                    delegatedListener.onResponse(null);
                                })
                        );
                    } else {
                        logger.error("Failed creating LOG_TYPE_INDEX", e);
                        listener.onFailure(e);
                    }
                }
            });
        } else {
            IndexMetadata metadata = state.getMetadata().index(LOG_TYPE_INDEX);
            if (getConfigIndexMappingVersion(metadata) < LOG_TYPE_MAPPING_VERSION) {
                // The index already exists but doesn't have our mapping
                client.admin()
                        .indices()
                        .preparePutMapping(LOG_TYPE_INDEX)
                        .setSource(logTypeIndexMapping(), XContentType.JSON)
                        .execute(ActionListener.delegateFailure(listener, (l, r) -> {
                            loadBuiltinLogTypes(ActionListener.delegateFailure(
                                    listener,
                                    (delegatedListener, unused) -> {
                                        isConfigIndexInitialized = true;
                                        delegatedListener.onResponse(null);
                                    })
                            );
                        }));
            } else {
                if (isConfigIndexInitialized) {
                    listener.onResponse(null);
                    return;
                }
                loadBuiltinLogTypes(ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, unused) -> {
                            isConfigIndexInitialized = true;
                            delegatedListener.onResponse(null);
                        })
                );
            }
        }
    }

    public void loadBuiltinLogTypes(ActionListener<Void> listener) {
        logger.info("Loading builtin types!");
        List<LogType> logTypes = builtinLogTypeLoader.getAllLogTypes();
        if (logTypes == null || logTypes.size() == 0) {
            logger.error("Failed loading builtin log types from disk!");
            listener.onFailure(SecurityAnalyticsException.wrap(
                    new IllegalStateException("Failed loading builtin log types from disk!"))
            );
            return;
        }
        List<FieldMappingDoc> fieldMappingDocs = createFieldMappingDocs(logTypes);
        logger.info("Indexing [" + fieldMappingDocs.size() + "] fieldMappingDocs from logTypes: " + logTypes.size());
        doIndexFieldMappings(fieldMappingDocs, listener);
    }
    /**
     * Loops through all builtin LogTypes and creates collection of FieldMappingDocs
     * */
    private List<FieldMappingDoc> createFieldMappingDocs(List<LogType> logTypes) {
        Map<String, FieldMappingDoc> fieldMappingMap = new HashMap<>();

        logTypes.stream()
                .filter(e -> e.getMappings() != null)
                .forEach( logType -> logType.getMappings().forEach(mapping -> {
                    // key is rawField + defaultSchemaField(ecs)
                    String key = mapping.getRawField() + "|" + mapping.getEcs();
                    FieldMappingDoc existingDoc = fieldMappingMap.get(key);
                    if (existingDoc == null) {
                        // create new doc
                        Map<String, String> schemaFields = new HashMap<>();
                        if (mapping.getEcs() != null) {
                            schemaFields.put("ecs", mapping.getEcs());
                        }
                        if (mapping.getOcsf() != null) {
                            schemaFields.put("ocsf", mapping.getOcsf());
                        }
                        fieldMappingMap.put(
                                key,
                                new FieldMappingDoc(
                                        mapping.getRawField(),
                                        schemaFields,
                                        Sets.newHashSet(logType.getName())
                                )
                        );
                    } else {
                        // merge with existing doc
                        existingDoc.getSchemaFields().put("ocsf", mapping.getOcsf());
                        existingDoc.getLogTypes().add(logType.getName());
                    }
                }));
        return fieldMappingMap.values().stream().collect(Collectors.toList());
    }

    public String logTypeIndexMapping() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(LOG_TYPE_INDEX_MAPPING_FILE)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            logger.error(
                    () -> new ParameterizedMessage("failed to load log-type-index mapping file [{}]", LOG_TYPE_INDEX_MAPPING_FILE),
                    e
            );
            throw new IllegalStateException("failed to load log-type-index mapping file [" + LOG_TYPE_INDEX_MAPPING_FILE + "]", e);
        }

    }

    private Settings logTypeIndexSettings() {
        return Settings.builder().put(IndexMetadata.INDEX_HIDDEN_SETTING.getKey(), "true").build();
    }

    private int getConfigIndexMappingVersion(IndexMetadata metadata) {
        MappingMetadata mappingMetadata = metadata.mapping();
        if (mappingMetadata == null) {
            return 0;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) mappingMetadata.sourceAsMap().get("_meta");
        if (meta == null || meta.containsKey(LOG_TYPE_MAPPING_VERSION_META_FIELD) == false) {
            return 1; // The mapping was created before meta field was introduced
        }
        return (int) meta.get(LOG_TYPE_MAPPING_VERSION_META_FIELD);
    }

    public List<LogType> getAllBuiltinLogTypes() {
        return builtinLogTypeLoader.getAllLogTypes();
    }

    public void getRuleFieldMappings(ActionListener<Map<String, Map<String, String>>> listener) {
        ensureConfigIndexIsInitialized(ActionListener.wrap(() ->
            getAllFieldMappings(ActionListener.delegateFailure(
                    listener,
                    (delegatedListener, fieldMappingDocs) -> {
                        Map<String, Map<String, String>> mappings = new HashMap<>();
                        for (FieldMappingDoc fieldMappingDoc: fieldMappingDocs) {
                            Set<String> logTypes = fieldMappingDoc.getLogTypes();
                            if (logTypes != null) {
                                for (String logType: logTypes) {
                                    Map<String, String> mappingsByLogTypes = mappings.containsKey(logType)? mappings.get(logType): new HashMap<>();
                                    mappingsByLogTypes.put(fieldMappingDoc.getRawField(), fieldMappingDoc.getSchemaFields().get(defaultSchemaField));
                                    mappings.put(logType, mappingsByLogTypes);
                                }
                            }
                        }
                        delegatedListener.onResponse(mappings);
                    }
            ))
        ));
    }

    /**
     * Returns sigmaRule rawField to default_schema_field(ECS) mapping
     *
     * @param logType Log type
     * Returns Map of rawField to ecs field via listener
     */
    public void getRuleFieldMappings(String logType, ActionListener<Map<String, String>> listener) {

        if (builtinLogTypeLoader.logTypeExists(logType)) {
            LogType lt = builtinLogTypeLoader.getLogTypeByName(logType);
            if (lt.getMappings() == null) {
                listener.onResponse(Map.of());
            } else {
                listener.onResponse(
                    lt.getMappings()
                        .stream()
                        .collect(Collectors.toMap(LogType.Mapping::getRawField, LogType.Mapping::getEcs))
                );
            }
            return;
        }

        getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            Map<String, String> ruleFieldMappings = new HashMap<>(fieldMappingDocs.size());
                            fieldMappingDocs.forEach( e -> {
                                ruleFieldMappings.put(e.getRawField(), e.getSchemaFields().get(defaultSchemaField));
                            });
                            delegatedListener.onResponse(ruleFieldMappings);
                        }
                )
        );
        return;
    }

    public void getRuleFieldMappingsAllSchemas(String logType, ActionListener<List<LogType.Mapping>> listener) {

        if (builtinLogTypeLoader.logTypeExists(logType)) {
            LogType lt = builtinLogTypeLoader.getLogTypeByName(logType);
            if (lt.getMappings() == null) {
                listener.onResponse(List.of());
            } else {
                listener.onResponse(lt.getMappings());
            }
            return;
        }

        getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            List<LogType.Mapping> ruleFieldMappings = new ArrayList<>();
                            fieldMappingDocs.forEach( e -> {
                                ruleFieldMappings.add(new LogType.Mapping(e.getRawField(), e.getSchemaFields().get("ecs"), e.getSchemaFields().get("ocsf")));
                            });
                            delegatedListener.onResponse(ruleFieldMappings);
                        }
                )
        );
        return;
    }
    /**
     * Provides required fields for a log type in order for all rules to work
     * */
    public void getRequiredFields(String logType, ActionListener<List<LogType.Mapping>> listener) {

        getFieldMappingsByLogType(
                logType,
                ActionListener.delegateFailure(
                        listener,
                        (delegatedListener, fieldMappingDocs) -> {
                            List<LogType.Mapping> requiredFields = new ArrayList<>();
                            fieldMappingDocs.forEach( e -> {
                                LogType.Mapping requiredField = new LogType.Mapping(
                                        e.getRawField(),
                                        e.getSchemaFields().get(defaultSchemaField),
                                        e.getSchemaFields().get("ocsf")
                                );
                                requiredFields.add(requiredField);
                            });
                            delegatedListener.onResponse(requiredFields);
                        }
                )
        );
    }

    /**
     * Provides required fields for all log types in a form of map
     * */
    public void getRequiredFieldsForAllLogTypes(ActionListener<Map<String, Set<String>>> listener) {
        ensureConfigIndexIsInitialized(ActionListener.wrap(() ->
            getAllFieldMappings(
                    ActionListener.delegateFailure(
                            listener,
                            (delegatedListener, fieldMappingDocs) -> {
                                Map<String, Set<String>> requiredFieldsMap = new HashMap<>();
                                fieldMappingDocs.forEach( e -> {
                                    // Init sets if first time seeing this logType
                                    e.getLogTypes().forEach(logType -> {
                                        if (!requiredFieldsMap.containsKey(logType)) {
                                            requiredFieldsMap.put(logType, new HashSet<>());
                                        }
                                    });
                                    String requiredField = e.getSchemaFields().get(defaultSchemaField);
                                    if (requiredField == null) {
                                        requiredField = e.getRawField(); // Always fallback to rawField if defaultSchema one is missing
                                    }
                                    final String _requiredField = requiredField;
                                    e.getLogTypes().forEach(logType -> {
                                        requiredFieldsMap.get(logType).add(_requiredField);
                                    });

                                });
                                delegatedListener.onResponse(requiredFieldsMap);
                            }
                    )
            )
        ));
    }

    /**
     * Returns sigmaRule rawField to default_schema_field(ECS) mapping, but works with builtin types only!
     *
     * @param builtinLogType Built-in (prepackaged) Log type
     * @return Map of rawField to ecs field via listener
     */
    public Map<String, String> getRuleFieldMappingsForBuiltinLogType(String builtinLogType) {

        if (!builtinLogTypeLoader.logTypeExists(builtinLogType)) {
            return null;
        }

        LogType lt = builtinLogTypeLoader.getLogTypeByName(builtinLogType);
        if (lt.getMappings() == null) {
            return Map.of();
        } else {
            return lt.getMappings()
                        .stream()
                        .collect(Collectors.toMap(LogType.Mapping::getRawField, LogType.Mapping::getEcs));

        }
    }


    public String getDefaultSchemaField() {
        return defaultSchemaField;
    }
}