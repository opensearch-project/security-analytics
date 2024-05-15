package org.opensearch.securityanalytics.feed.store;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.securityanalytics.exceptions.FeedStoreException;
import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.index.IndexAccessor;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.STIX2;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.opensearch.securityanalytics.feed.store.SystemIndexFeedStore.ALIAS_NAME;
import static org.opensearch.securityanalytics.feed.store.SystemIndexFeedStore.HIDDEN_INDEX;
import static org.opensearch.securityanalytics.feed.store.SystemIndexFeedStore.IOC_DOC_ID_FORMAT;
import static org.opensearch.securityanalytics.feed.store.SystemIndexFeedStore.PRIMARY_SHARD_COUNT;

public class SystemIndexFeedStoreTests {
    private static final String FEED_ID = UUID.randomUUID().toString();
    private static final String IOC_ID = UUID.randomUUID().toString();

    @Mock
    private IndexAccessor indexAccessor;
    @Mock
    private BulkResponse bulkResponse;

    private SystemIndexFeedStore systemIndexFeedStore;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        systemIndexFeedStore = new SystemIndexFeedStore(indexAccessor);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(indexAccessor, bulkResponse);
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_Success(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        when(indexAccessor.bulk(any(BulkRequest.class))).thenReturn(bulkResponse);
        when(bulkResponse.hasFailures()).thenReturn(false);

        systemIndexFeedStore.storeIOCs(List.of(ioc), updateType);

        verifyCreateIndexIfPresent();
        if (updateType == UpdateType.REPLACE) {
            verifyDeleteByQuery();
        }
        verifyBulkIndexIOCs(List.of(ioc));
        verify(bulkResponse).hasFailures();
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_Success_MultipleIOCs(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        when(indexAccessor.bulk(any(BulkRequest.class))).thenReturn(bulkResponse);
        when(bulkResponse.hasFailures()).thenReturn(false);

        systemIndexFeedStore.storeIOCs(List.of(ioc, ioc, ioc, ioc), updateType);

        verifyCreateIndexIfPresent();
        if (updateType == UpdateType.REPLACE) {
            verifyDeleteByQuery();
        }
        verifyBulkIndexIOCs(List.of(ioc, ioc, ioc, ioc));
        verify(bulkResponse).hasFailures();
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_NoIOCs(final UpdateType updateType) {
        systemIndexFeedStore.storeIOCs(Collections.emptyList(), updateType);
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_TooManyFeedIds(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        final IOC ioc2 = getIOC(UUID.randomUUID().toString(), IOC_ID);

        assertThrows(FeedStoreException.class, () -> systemIndexFeedStore.storeIOCs(List.of(ioc, ioc2), updateType));
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_ExceptionCreatingIndex(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        doThrow(new RuntimeException()).when(indexAccessor).createRolloverAlias(eq(ALIAS_NAME), any(Settings.class), any(Map.class));

        assertThrows(FeedStoreException.class, () -> systemIndexFeedStore.storeIOCs(List.of(ioc), updateType));

        verifyCreateIndexIfPresent();
    }

    @Test
    public void testStoreIOCs_ExceptionDeletingByQuery() {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        doThrow(new RuntimeException()).when(indexAccessor).deleteByQuery(eq(ALIAS_NAME), any(QueryBuilder.class));

        assertThrows(FeedStoreException.class, () -> systemIndexFeedStore.storeIOCs(List.of(ioc), UpdateType.REPLACE));

        verifyCreateIndexIfPresent();
        verifyDeleteByQuery();
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_ExceptionBulkingIOCs(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        when(indexAccessor.bulk(any(BulkRequest.class))).thenThrow(new RuntimeException());

        assertThrows(FeedStoreException.class, () -> systemIndexFeedStore.storeIOCs(List.of(ioc), updateType));

        verifyCreateIndexIfPresent();
        if (updateType == UpdateType.REPLACE) {
            verifyDeleteByQuery();
        }
        verifyBulkIndexIOCs(List.of(ioc));
    }

    @ParameterizedTest
    @MethodSource("getUpdateTypes")
    public void testStoreIOCs_BulkResponseHasFailures(final UpdateType updateType) {
        final IOC ioc = getIOC(FEED_ID, IOC_ID);
        when(indexAccessor.bulk(any(BulkRequest.class))).thenReturn(bulkResponse);
        when(bulkResponse.hasFailures()).thenReturn(true);

        assertThrows(FeedStoreException.class, () -> systemIndexFeedStore.storeIOCs(List.of(ioc), updateType));

        verifyCreateIndexIfPresent();
        if (updateType == UpdateType.REPLACE) {
            verifyDeleteByQuery();
        }
        verifyBulkIndexIOCs(List.of(ioc));
        verify(bulkResponse).hasFailures();
        verify(bulkResponse).buildFailureMessage();
    }

    private void verifyCreateIndexIfPresent() {
        final ArgumentCaptor<Settings> captor = ArgumentCaptor.forClass(Settings.class);
        final ArgumentCaptor<Map<String, Object>> rolloverCaptor = ArgumentCaptor.forClass(Map.class);
        verify(indexAccessor).createRolloverAlias(eq(ALIAS_NAME), captor.capture(), rolloverCaptor.capture());

        assertTrue(captor.getValue().hasValue(IndexAccessor.SHARD_COUNT_SETTING_NAME));
        assertEquals("" + PRIMARY_SHARD_COUNT, captor.getValue().get(IndexAccessor.SHARD_COUNT_SETTING_NAME));
        assertTrue(captor.getValue().hasValue(IndexAccessor.AUTO_EXPAND_REPLICA_COUNT_SETTING_NAME));
        assertEquals(IndexAccessor.EXPAND_ALL_REPLICA_COUNT_SETTING_VALUE, captor.getValue().get(IndexAccessor.AUTO_EXPAND_REPLICA_COUNT_SETTING_NAME));
        assertTrue(captor.getValue().hasValue(IndexAccessor.HIDDEN_INDEX_SETTING_NAME));
        assertEquals(String.valueOf(HIDDEN_INDEX), captor.getValue().get(IndexAccessor.HIDDEN_INDEX_SETTING_NAME));
    }

    private void verifyDeleteByQuery() {
        final ArgumentCaptor<QueryBuilder> captor = ArgumentCaptor.forClass(QueryBuilder.class);
        verify(indexAccessor).deleteByQuery(eq(ALIAS_NAME), captor.capture());

        assertNotNull(captor.getValue());
    }

    private void verifyBulkIndexIOCs(final List<IOC> iocs) {
        final ArgumentCaptor<BulkRequest> captor = ArgumentCaptor.forClass(BulkRequest.class);
        verify(indexAccessor).bulk(captor.capture());

        assertEquals(iocs.size(), captor.getValue().requests().size());
        IntStream.range(0, iocs.size()).forEach(i -> {
            final IndexRequest indexRequest = (IndexRequest) captor.getValue().requests().get(i);
            assertEquals(ALIAS_NAME, indexRequest.index());
            assertEquals(String.format(IOC_DOC_ID_FORMAT, FEED_ID, IOC_ID), indexRequest.id());
        });
    }

    private static Stream<Arguments> getUpdateTypes() {
        return Arrays.stream(UpdateType.values())
                .map(Arguments::of);
    }

    private IOC getIOC(final String feedId, final String iocId) {
        final IOC ioc = new STIX2();
        ioc.setFeedId(feedId);
        ioc.setId(iocId);

        return ioc;
    }
}
