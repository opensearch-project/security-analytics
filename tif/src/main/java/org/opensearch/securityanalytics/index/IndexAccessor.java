package org.opensearch.securityanalytics.index;

import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.unit.ByteSizeUnit;
import org.opensearch.core.common.unit.ByteSizeValue;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;

import java.util.Map;

public interface IndexAccessor {
    String SHARD_COUNT_SETTING_NAME = "index.number_of_shards";
    String AUTO_EXPAND_REPLICA_COUNT_SETTING_NAME = "index.auto_expand_replicas";
    String EXPAND_ALL_REPLICA_COUNT_SETTING_VALUE = "0-all";
    String HIDDEN_INDEX_SETTING_NAME = "index.hidden";
    String ROLLOVER_INDEX_FORMAT = "%s-000001";
    String INDEX_PATTERN_FORMAT = "%s*";
    //String ROLLOVER_INDEX_SIZE_SETTING_NAME = "min_primary_shard_size";
    //String DEFAULT_ROLLOVER_INDEX_SIZE_SETTING_VALUE = new ByteSizeValue(30, ByteSizeUnit.GB).getStringRep();
    String ROLLOVER_INDEX_SIZE_SETTING_NAME = "min_doc_count";
    String DEFAULT_ROLLOVER_INDEX_SIZE_SETTING_VALUE = "1";
    String INDEX_ROLLOVER_ALIAS_SETTING_NAME = "index.plugins.index_state_management.rollover_alias";

    /**
     * Creates a rollover alias if it is not already present. This consists of 3 steps:
     * 1. Create an index template based on the provided settings
     * 2. Create an ISM policy with the provided rollover conditions
     * 3. Create the initial write index with the rollover alias attached
     *
     * @param aliasName - the name of the rollover alias
     * @param settings - the settings to apply to the index
     * @param rolloverConfiguration - a map of the rollover setting name to its value
     */
    void createRolloverAlias(String aliasName, Settings settings, Map<String, Object> rolloverConfiguration);

    /**
     * Deletes a rollover alias by name. Also deletes the ISM policy, indices that match the alias pattern, and the index template
     * associated with the alias.
     *
     * @param aliasName - the name of the alias
     */
    void deleteRolloverAlias(String aliasName);

    /**
     * Deletes a set of documents that match the provided query
     *
     * @param indexName - the name of the index to delete from
     * @param queryBuilder - the filter conditions for the delete-by-query
     * @return BulkByScrollResponse - the results of the delete-by-query execution
     */
    BulkByScrollResponse deleteByQuery(String indexName, QueryBuilder queryBuilder);

    /**
     * Executes a bulk request
     *
     * @param bulkRequest - the request to execute
     * @return BulkResponse - the results of the bulk execution
     */
    BulkResponse bulk(BulkRequest bulkRequest);
}
