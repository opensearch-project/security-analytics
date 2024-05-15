package org.opensearch.securityanalytics.feed.retriever;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.connector.IOCConnector;
import org.opensearch.securityanalytics.feed.store.FeedStore;
import org.opensearch.securityanalytics.feed.store.model.UpdateType;
import org.opensearch.securityanalytics.model.IOC;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class FeedRetrieverTests {
    private static final UpdateType UPDATE_TYPE = UpdateType.REPLACE;
    private static final String FEED_ID = UUID.randomUUID().toString();

    @Mock
    private IOCConnector iocConnector;
    @Mock
    private FeedStore feedStore;
    @Mock
    private IOC ioc;

    private FeedRetriever feedRetriever;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        feedRetriever = new FeedRetriever(iocConnector, feedStore, UPDATE_TYPE, FEED_ID);
    }

    @AfterEach
    public void teardown() {
        verifyNoMoreInteractions(iocConnector, feedStore, ioc);
    }

    @Test
    public void testRun() {
        when(iocConnector.loadIOCs()).thenReturn(List.of(ioc));

        feedRetriever.run();

        verify(iocConnector).loadIOCs();
        verify(feedStore).storeIOCs(eq(List.of(ioc)), eq(UPDATE_TYPE));
    }

    @Test
    public void testRun_ExceptionLoadingIOCs_DoesNotThrow() {
        when(iocConnector.loadIOCs()).thenThrow(new RuntimeException());

        feedRetriever.run();

        verify(iocConnector).loadIOCs();
    }

    @Test
    public void testRun_ExceptionStoringIOCs_DoesNotThrow() {
        when(iocConnector.loadIOCs()).thenReturn(List.of(ioc));
        doThrow(new RuntimeException()).when(feedStore).storeIOCs(eq(List.of(ioc)), eq(UPDATE_TYPE));

        feedRetriever.run();

        verify(iocConnector).loadIOCs();
        verify(feedStore).storeIOCs(eq(List.of(ioc)), eq(UPDATE_TYPE));
    }
}
