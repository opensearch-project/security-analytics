package org.opensearch.securityanalytics.feed;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class FeedManagerTests {
    private static final String FEED_ID = UUID.randomUUID().toString();

    @Mock
    private ScheduledExecutorService scheduledExecutorService;
    @Mock
    private Runnable feedRetriever;
    @Mock
    private ScheduledFuture feedRetrieverFuture;

    private Map<String, ScheduledFuture<?>> registeredTasks;
    private FeedManager feedManager;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        registeredTasks = new HashMap<>();
        feedManager = new FeedManager(scheduledExecutorService, registeredTasks);
    }

    @AfterEach
    public void teardown() {
        verifyNoMoreInteractions(scheduledExecutorService, feedRetriever, feedRetrieverFuture);
    }

    @Test
    public void testRegisterFeedRetriever() {
        final long millisDuration = new Random().nextLong();
        when(scheduledExecutorService.scheduleAtFixedRate(eq(feedRetriever), eq(0L), eq(millisDuration), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(feedRetrieverFuture);

        feedManager.registerFeedRetriever(FEED_ID, feedRetriever, Duration.ofMillis(millisDuration));

        assertEquals(1, registeredTasks.size());
        assertTrue(registeredTasks.containsKey(FEED_ID));
        assertEquals(feedRetrieverFuture, registeredTasks.get(FEED_ID));

        verify(scheduledExecutorService).scheduleAtFixedRate(eq(feedRetriever), eq(0L), eq(millisDuration), eq(TimeUnit.MILLISECONDS));
    }

    @Test
    public void testDeregisterFeedRetriever() {
        registeredTasks.put(FEED_ID, feedRetrieverFuture);
        assertEquals(1, registeredTasks.size());

        feedManager.deregisterFeedRetriever(FEED_ID);

        assertTrue(registeredTasks.isEmpty());
        verify(feedRetrieverFuture).cancel(eq(true));
    }

    @Test
    public void testDeregisterFeedRetriever_FeedNotRegistered() {
        registeredTasks.put(UUID.randomUUID().toString(), feedRetrieverFuture);
        assertEquals(1, registeredTasks.size());

        feedManager.deregisterFeedRetriever(FEED_ID);

        assertEquals(1, registeredTasks.size());
        assertFalse(registeredTasks.containsKey(FEED_ID));
    }

    @Test
    public void testRegisterFeedRetriever_FeedAlreadyRegistered() {
        registeredTasks.put(FEED_ID, feedRetrieverFuture);

        final long millisDuration = new Random().nextLong();
        when(scheduledExecutorService.scheduleAtFixedRate(eq(feedRetriever), eq(0L), eq(millisDuration), eq(TimeUnit.MILLISECONDS)))
                .thenReturn(feedRetrieverFuture);

        feedManager.registerFeedRetriever(FEED_ID, feedRetriever, Duration.ofMillis(millisDuration));

        assertEquals(1, registeredTasks.size());
        assertTrue(registeredTasks.containsKey(FEED_ID));
        assertEquals(feedRetrieverFuture, registeredTasks.get(FEED_ID));

        verify(scheduledExecutorService).scheduleAtFixedRate(eq(feedRetriever), eq(0L), eq(millisDuration), eq(TimeUnit.MILLISECONDS));
        verify(feedRetrieverFuture).cancel(eq(true));
    }
}
