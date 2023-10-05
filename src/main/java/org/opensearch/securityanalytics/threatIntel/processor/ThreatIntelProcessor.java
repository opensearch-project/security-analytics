/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.processor;

import static org.opensearch.ingest.ConfigurationUtils.newConfigurationException;
import static org.opensearch.ingest.ConfigurationUtils.readBooleanProperty;
import static org.opensearch.ingest.ConfigurationUtils.readOptionalList;
import static org.opensearch.ingest.ConfigurationUtils.readStringProperty;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import org.opensearch.common.settings.ClusterSettings;

import org.opensearch.ingest.AbstractProcessor;
import org.opensearch.ingest.IngestDocument;
import org.opensearch.ingest.IngestService;
import org.opensearch.ingest.Processor;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ParameterValidator;
import org.opensearch.securityanalytics.threatIntel.dao.DatasourceDao;
import org.opensearch.securityanalytics.threatIntel.dao.ThreatIntelCachedDao;

/**
 * threat intel processor
 */
public final class ThreatIntelProcessor extends AbstractProcessor {
    public static final String CONFIG_FIELD = "field";
    public static final String CONFIG_TARGET_FIELD = "target_field";
    public static final String CONFIG_DATASOURCE = "datasource";
    public static final String CONFIG_PROPERTIES = "properties";
    public static final String CONFIG_IGNORE_MISSING = "ignore_missing";

    private final String field;
    private final String targetField;

    public String getDatasourceName() {
        return datasourceName;
    }

    /**
     * @return The datasource name
     */
    private final String datasourceName;
    private final Set<String> properties;
    private final boolean ignoreMissing;
    private final ClusterSettings clusterSettings;
    private final DatasourceDao datasourceDao;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final ThreatIntelCachedDao threatIntelCachedDao;

    /**
     * Threat intel processor type
     */
    public static final String TYPE = "threatintel";

    /**
     * Construct an Threat intel processor.
     * @param tag            the processor tag
     * @param description    the processor description
     * @param field          the source field to threat intel feed map
     * @param targetField    the target field
     * @param datasourceName the datasourceName
     * @param properties     the properties
     * @param ignoreMissing  true if documents with a missing value for the field should be ignored
     * @param clusterSettings the cluster settings
     * @param datasourceDao the datasource facade
     * @param threatIntelFeedDataService the threat intel feed data facade
     * @param threatIntelCachedDao the cache
     */
    public ThreatIntelProcessor(
            final String tag,
            final String description,
            final String field,
            final String targetField,
            final String datasourceName,
            final Set<String> properties,
            final boolean ignoreMissing,
            final ClusterSettings clusterSettings,
            final DatasourceDao datasourceDao,
            final ThreatIntelFeedDataService threatIntelFeedDataService,
            final ThreatIntelCachedDao threatIntelCachedDao
    ) {
        super(tag, description);
        this.field = field;
        this.targetField = targetField;
        this.datasourceName = datasourceName;
        this.properties = properties;
        this.ignoreMissing = ignoreMissing;
        this.clusterSettings = clusterSettings;
        this.datasourceDao = datasourceDao;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.threatIntelCachedDao = threatIntelCachedDao;
    }

    /**
     * Add threat intel feed data of a given ip address to ingestDocument in asynchronous way
     *
     * @param ingestDocument the document
     * @param handler the handler
     */
    @Override
    public void execute(IngestDocument ingestDocument, BiConsumer<IngestDocument, Exception> handler) {
        try {
            Object ip = ingestDocument.getFieldValue(field, Object.class, ignoreMissing);

            if (ip == null) {
                handler.accept(ingestDocument, null);
                return;
            }

            if (ip instanceof String) {
                executeInternal(ingestDocument, handler, (String) ip);
            } else if (ip instanceof List) {
                executeInternal(ingestDocument, handler, ((List<?>) ip));
            } else {
                handler.accept(
                        null,
                        new IllegalArgumentException(
                                String.format(Locale.ROOT, "field [%s] should contain only string or array of strings", field)
                        )
                );
            }
        } catch (Exception e) {
            handler.accept(null, e);
        }
    }

    /**
     * Use {@code execute(IngestDocument, BiConsumer<IngestDocument, Exception>)} instead
     *
     * @param ingestDocument the document
     * @return none
     */
    @Override
    public IngestDocument execute(IngestDocument ingestDocument) {
        throw new IllegalStateException("Not implemented");
    }

    private void executeInternal(
            final IngestDocument ingestDocument,
            final BiConsumer<IngestDocument, Exception> handler,
            final String ip
    ) {
        validateDatasourceIsInAvailableState(datasourceName);
        String indexName = threatIntelCachedDao.getIndexName(datasourceName);

        Map<String, Object> threatIntelData = threatIntelCachedDao.getThreatIntelData(indexName, ip);
        if (threatIntelData.isEmpty() == false) {
            ingestDocument.setFieldValue(targetField, filteredThreatIntelData(threatIntelData));
        }
        handler.accept(ingestDocument, null);
    }

    private Map<String, Object> filteredThreatIntelData(final Map<String, Object> threatIntelData) {
        if (properties == null) {
            return threatIntelData;
        }

        return properties.stream().filter(p -> threatIntelData.containsKey(p)).collect(Collectors.toMap(p -> p, p -> threatIntelData.get(p)));
    }

    private void validateDatasourceIsInAvailableState(final String datasourceName) {
        if (threatIntelCachedDao.has(datasourceName) == false) {
            throw new IllegalStateException("datasource does not exist");
        }

        if (DatasourceState.AVAILABLE.equals(threatIntelCachedDao.getState(datasourceName)) == false) {
            throw new IllegalStateException("datasource is not in an available state");
        }
    }

    /**
     * Handle multiple ips
     *
     * @param ingestDocument the document
     * @param handler the handler
     * @param ips the ip list
     */
    private void executeInternal(
            final IngestDocument ingestDocument,
            final BiConsumer<IngestDocument, Exception> handler,
            final List<?> ips
    ) {
        for (Object ip : ips) {
            if (ip instanceof String == false) {
                throw new IllegalArgumentException("array in field [" + field + "] should only contain strings");
            }
        }

        validateDatasourceIsInAvailableState(datasourceName);
        String indexName = threatIntelCachedDao.getIndexName(datasourceName);

        List<Map<String, Object>> threatIntelDataList = ips.stream()
                .map(ip -> threatIntelCachedDao.getThreatIntelData(indexName, (String) ip))
                .filter(threatIntelData -> threatIntelData.isEmpty() == false)
                .map(this::filteredThreatIntelData)
                .collect(Collectors.toList());

        if (threatIntelDataList.isEmpty() == false) {
            ingestDocument.setFieldValue(targetField, threatIntelDataList);
        }
        handler.accept(ingestDocument, null);
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /**
     * threat intel processor factory
     */
    public static final class Factory implements Processor.Factory {
        private static final ParameterValidator VALIDATOR = new ParameterValidator();
        private final IngestService ingestService;
        private final DatasourceDao datasourceDao;
        private final ThreatIntelFeedDataService threatIntelFeedDataService;
        private final ThreatIntelCachedDao threatIntelCachedDao;

        public Factory(
                final IngestService ingestService,
                final DatasourceDao datasourceDao,
                final ThreatIntelFeedDataService threatIntelFeedDataService,
                final ThreatIntelCachedDao threatIntelCachedDao
        ) {
            this.ingestService = ingestService;
            this.datasourceDao = datasourceDao;
            this.threatIntelFeedDataService = threatIntelFeedDataService;
            this.threatIntelCachedDao = threatIntelCachedDao;
        }

        /**
         * Within this method, blocking request cannot be called because this method is executed in a transport thread.
         * This means, validation using data in an index won't work.
         */
        @Override
        public ThreatIntelProcessor create(
                final Map<String, Processor.Factory> registry,
                final String processorTag,
                final String description,
                final Map<String, Object> config
        ) throws IOException {
            String ipField = readStringProperty(TYPE, processorTag, config, CONFIG_FIELD);
            String targetField = readStringProperty(TYPE, processorTag, config, CONFIG_TARGET_FIELD, "threatintel");
            String datasourceName = readStringProperty(TYPE, processorTag, config, CONFIG_DATASOURCE);
            List<String> propertyNames = readOptionalList(TYPE, processorTag, config, CONFIG_PROPERTIES);
            boolean ignoreMissing = readBooleanProperty(TYPE, processorTag, config, CONFIG_IGNORE_MISSING, false);

            List<String> error = VALIDATOR.validateDatasourceName(datasourceName);
            if (error.isEmpty() == false) {
                throw newConfigurationException(TYPE, processorTag, "datasource", error.get(0));
            }

            return new ThreatIntelProcessor(
                    processorTag,
                    description,
                    ipField,
                    targetField,
                    datasourceName,
                    propertyNames == null ? null : new HashSet<>(propertyNames),
                    ignoreMissing,
                    ingestService.getClusterService().getClusterSettings(),
                    datasourceDao,
                    threatIntelFeedDataService,
                    threatIntelCachedDao
            );
        }
    }
}
