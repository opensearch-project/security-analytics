package org.opensearch.securityanalytics.feed.store;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.securityanalytics.exceptions.FeedStoreException;
import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.index.IndexAccessor;
import org.opensearch.securityanalytics.model.IOC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class SystemIndexFeedStore implements FeedStore {
    private static final Logger log = LoggerFactory.getLogger(SystemIndexFeedStore.class);

    // TODO - alias with rollover
    static final String ALIAS_NAME = ".opensearch-sap-tif-store";
    static final int PRIMARY_SHARD_COUNT = 1;
    static final boolean HIDDEN_INDEX = true;
    static final String IOC_DOC_ID_FORMAT = "%s-%s";

    private final IndexAccessor indexAccessor;
    private final ObjectMapper objectMapper;

    public SystemIndexFeedStore(final IndexAccessor indexAccessor) {
        this.indexAccessor = indexAccessor;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void storeIOCs(final List<IOC> iocs, final UpdateType updateType) {
        if (iocs.isEmpty()) {
            log.info("No IOCs found, skipping update");
            return;
        }

        try {
            validateIOCs(iocs);
            setupFeedIndex(updateType, iocs.get(0).getFeedId());
            updateFeedIndex(iocs);
        } catch (final Exception e) {
            throw new FeedStoreException("Exception updating feed store for feed ID: " + iocs.get(0).getFeedId(), e);
        }
    }

    private void validateIOCs(final List<IOC> iocs) {
        final Set<String> feedIds = iocs.stream()
                .map(IOC::getFeedId)
                .collect(Collectors.toSet());

        if (feedIds.size() != 1) {
            throw new IllegalArgumentException("Exactly one feed should be updated at a time. Found feed IDs: " + feedIds);
        }
    }

    private void setupFeedIndex(final UpdateType updateType, final String feedId) {
        indexAccessor.createRolloverAlias(ALIAS_NAME, createRolloverAliasSettings(), createISMPolicyRolloverConfiguration());

        /* TODO - this probably needs locking for consistency. The IOC scan done by the TIF platform could read a partial state
           The tradeoff is that it may take seconds if not minutes to update the feed system index. Do we want to block scanning
           during that time or live with a potentially inconsistent state? */
        if (UpdateType.REPLACE.equals(updateType)) {
            indexAccessor.deleteByQuery(ALIAS_NAME, deleteByQueryBuilder(feedId));
        }
    }

    private QueryBuilder deleteByQueryBuilder(final String feedId) {
        return QueryBuilders.matchQuery(IOC.FEED_ID_FIELD_NAME, feedId);
    }

    private Settings createRolloverAliasSettings() {
        return Settings.builder()
                .put(IndexAccessor.SHARD_COUNT_SETTING_NAME, PRIMARY_SHARD_COUNT)
                .put(IndexAccessor.AUTO_EXPAND_REPLICA_COUNT_SETTING_NAME, IndexAccessor.EXPAND_ALL_REPLICA_COUNT_SETTING_VALUE)
                .put(IndexAccessor.HIDDEN_INDEX_SETTING_NAME, HIDDEN_INDEX)
                .put(IndexAccessor.INDEX_ROLLOVER_ALIAS_SETTING_NAME, ALIAS_NAME)
                .build();
    }

    private Map<String, Object> createISMPolicyRolloverConfiguration() {
        return Map.of(
                IndexAccessor.ROLLOVER_INDEX_SIZE_SETTING_NAME, IndexAccessor.DEFAULT_ROLLOVER_INDEX_SIZE_SETTING_VALUE
        );
    }

    private void updateFeedIndex(final List<IOC> iocs) {
        // TODO - paginate. can be GBs of IOCs
        final BulkRequest bulkRequest = bulkRequest(iocs);
        final BulkResponse bulkResponse = indexAccessor.bulk(bulkRequest);

        if (bulkResponse.hasFailures()) {
            throw new FeedStoreException(bulkResponse.buildFailureMessage());
        }
    }

    private BulkRequest bulkRequest(final List<IOC> iocs) {
        final List<DocWriteRequest<?>> bulkActions = iocs.stream()
                .map(this::indexRequest)
                .collect(Collectors.toList());

        return new BulkRequest().add(bulkActions);
    }

    private IndexRequest indexRequest(final IOC ioc) {
        // TODO - nearly positive you can just index a POJO. Need to investigate how to do that instead of expensively converting each to a Map
        final Map<String, ?> iocAsMap = objectMapper.convertValue(ioc, new TypeReference<>() {});
        return new IndexRequest(ALIAS_NAME)
                .source(iocAsMap, XContentType.JSON)
                .id(docId(ioc));
    }

    private String docId(final IOC ioc) {
        return String.format(IOC_DOC_ID_FORMAT, ioc.getFeedId(), ioc.getId());
    }
}
