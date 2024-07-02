/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel;

import org.junit.After;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Randomness;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.ingest.IngestMetadata;
import org.opensearch.ingest.IngestService;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.feedMetadata.BuiltInTIFMetadataLoader;
import org.opensearch.securityanalytics.threatIntel.model.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.service.TIFJobUpdateService;
import org.opensearch.securityanalytics.threatIntel.service.DetectorThreatIntelService;
import org.opensearch.securityanalytics.threatIntel.service.ThreatIntelFeedDataService;
import org.opensearch.tasks.Task;
import org.opensearch.tasks.TaskListener;
import org.opensearch.test.client.NoOpNodeClient;
import org.opensearch.test.rest.RestActionTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import org.opensearch.securityanalytics.TestHelpers;

public abstract class ThreatIntelTestCase extends RestActionTestCase {
    @Mock
    protected ClusterService clusterService;
    @Mock
    protected TIFJobUpdateService tifJobUpdateService;
    @Mock
    protected TIFJobParameterService tifJobParameterService;
    @Mock
    protected BuiltInTIFMetadataLoader builtInTIFMetadataLoader;
    @Mock
    protected ThreatIntelFeedDataService threatIntelFeedDataService;
    @Mock
    protected ClusterState clusterState;
    @Mock
    protected Metadata metadata;
    @Mock
    protected IngestService ingestService;
    @Mock
    protected ActionFilters actionFilters;
    @Mock
    protected ThreadPool threadPool;
    @Mock
    protected TIFLockService tifLockService;
    @Mock
    protected RoutingTable routingTable;
    @Mock
    protected TransportService transportService;
    protected IngestMetadata ingestMetadata;
    protected NoOpNodeClient client;
    protected VerifyingClient verifyingClient;
    protected LockService lockService;
    protected ClusterSettings clusterSettings;
    protected Settings settings;
    private AutoCloseable openMocks;
    @Mock
    protected DetectorThreatIntelService detectorThreatIntelService;
    @Mock
    protected TIFJobParameter tifJobParameter;

    @Before
    public void prepareThreatIntelTestCase() {
        openMocks = MockitoAnnotations.openMocks(this);
        settings = Settings.EMPTY;
        client = new NoOpNodeClient(this.getTestName());
        verifyingClient = spy(new VerifyingClient(this.getTestName()));
        clusterSettings = new ClusterSettings(settings, new HashSet<>(SecurityAnalyticsSettings.settings()));
        lockService = new LockService(client, clusterService);
        ingestMetadata = new IngestMetadata(Collections.emptyMap());
        when(metadata.custom(IngestMetadata.TYPE)).thenReturn(ingestMetadata);
        when(clusterService.getSettings()).thenReturn(Settings.EMPTY);
        when(clusterService.getClusterSettings()).thenReturn(clusterSettings);
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterState.metadata()).thenReturn(metadata);
        when(clusterState.getMetadata()).thenReturn(metadata);
        when(clusterState.routingTable()).thenReturn(routingTable);
        when(ingestService.getClusterService()).thenReturn(clusterService);
        when(threadPool.generic()).thenReturn(OpenSearchExecutors.newDirectExecutorService());
        detectorThreatIntelService = new DetectorThreatIntelService(threatIntelFeedDataService, client, xContentRegistry());
    }

    @After
    public void clean() throws Exception {
        openMocks.close();
        client.close();
        verifyingClient.close();
    }

    protected TIFJobState randomStateExcept(TIFJobState state) {
        assertNotNull(state);
        return Arrays.stream(TIFJobState.values())
                .sequential()
                .filter(s -> !s.equals(state))
                .collect(Collectors.toList())
                .get(Randomness.createSecure().nextInt(TIFJobState.values().length - 2));
    }

    protected TIFJobState randomState() {
        return Arrays.stream(TIFJobState.values())
                .sequential()
                .collect(Collectors.toList())
                .get(Randomness.createSecure().nextInt(TIFJobState.values().length - 1));
    }

    protected long randomPositiveLong() {
        long value = Randomness.get().nextLong();
        return value < 0 ? -value : value;
    }

    /**
     * Update interval should be > 0 and < validForInDays.
     * For an update test to work, there should be at least one eligible value other than current update interval.
     * Therefore, the smallest value for validForInDays is 2.
     * Update interval is random value from 1 to validForInDays - 2.
     * The new update value will be validForInDays - 1.
     */
    protected TIFJobParameter randomTifJobParameter(final Instant updateStartTime) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        TIFJobParameter tifJobParameter = new TIFJobParameter();
        tifJobParameter.setName(TestHelpers.randomLowerCaseString());
        tifJobParameter.setSchedule(
                new IntervalSchedule(
                        updateStartTime.truncatedTo(ChronoUnit.MILLIS),
                        1,
                        ChronoUnit.DAYS
                )
        );
        tifJobParameter.setState(randomState());
        tifJobParameter.setIndices(Arrays.asList(TestHelpers.randomLowerCaseString(), TestHelpers.randomLowerCaseString()));
        tifJobParameter.getUpdateStats().setLastSkippedAt(now);
        tifJobParameter.getUpdateStats().setLastSucceededAt(now);
        tifJobParameter.getUpdateStats().setLastFailedAt(now);
        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        tifJobParameter.setLastUpdateTime(now);
        if (Randomness.get().nextInt() % 2 == 0) {
            tifJobParameter.enable();
        } else {
            tifJobParameter.disable();
        }
        return tifJobParameter;
    }

    protected TIFJobParameter randomTifJobParameter() {
        return randomTifJobParameter(Instant.now());
    }

    protected LockModel randomLockModel() {
        LockModel lockModel = new LockModel(
                TestHelpers.randomLowerCaseString(),
                TestHelpers.randomLowerCaseString(),
                Instant.now(),
                randomPositiveLong(),
                false
        );
        return lockModel;
    }

    /**
     * Temporary class of VerifyingClient until this PR(https://github.com/opensearch-project/OpenSearch/pull/7167)
     * is merged in OpenSearch core
     */
    public static class VerifyingClient extends NoOpNodeClient {
        AtomicReference<BiFunction> executeVerifier = new AtomicReference<>();
        AtomicReference<BiFunction> executeLocallyVerifier = new AtomicReference<>();

        public VerifyingClient(String testName) {
            super(testName);
            reset();
        }

        /**
         * Clears any previously set verifier functions set by {@link #setExecuteVerifier(BiFunction)} and/or
         * {@link #setExecuteLocallyVerifier(BiFunction)}. These functions are replaced with functions which will throw an
         * {@link AssertionError} if called.
         */
        public void reset() {
            executeVerifier.set((arg1, arg2) -> { throw new AssertionError(); });
            executeLocallyVerifier.set((arg1, arg2) -> { throw new AssertionError(); });
        }

        /**
         * Sets the function that will be called when {@link #doExecute(ActionType, ActionRequest, ActionListener)} is called. The given
         * function should return either a subclass of {@link ActionResponse} or {@code null}.
         * @param verifier A function which is called in place of {@link #doExecute(ActionType, ActionRequest, ActionListener)}
         */
        public <Request extends ActionRequest, Response extends ActionResponse> void setExecuteVerifier(
                BiFunction<ActionType<Response>, Request, Response> verifier
        ) {
            executeVerifier.set(verifier);
        }

        @Override
        public <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                ActionType<Response> action,
                Request request,
                ActionListener<Response> listener
        ) {
            try {
                listener.onResponse((Response) executeVerifier.get().apply(action, request));
            } catch (Exception e) {
                listener.onFailure(e);
            }
        }

        /**
         * Sets the function that will be called when {@link #executeLocally(ActionType, ActionRequest, TaskListener)}is called. The given
         * function should return either a subclass of {@link ActionResponse} or {@code null}.
         * @param verifier A function which is called in place of {@link #executeLocally(ActionType, ActionRequest, TaskListener)}
         */
        public <Request extends ActionRequest, Response extends ActionResponse> void setExecuteLocallyVerifier(
                BiFunction<ActionType<Response>, Request, Response> verifier
        ) {
            executeLocallyVerifier.set(verifier);
        }

        @Override
        public <Request extends ActionRequest, Response extends ActionResponse> Task executeLocally(
                ActionType<Response> action,
                Request request,
                ActionListener<Response> listener
        ) {
            listener.onResponse((Response) executeLocallyVerifier.get().apply(action, request));
            return null;
        }

        @Override
        public <Request extends ActionRequest, Response extends ActionResponse> Task executeLocally(
                ActionType<Response> action,
                Request request,
                TaskListener<Response> listener
        ) {
            listener.onResponse(null, (Response) executeLocallyVerifier.get().apply(action, request));
            return null;
        }

    }
}

