/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

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
import org.opensearch.securityanalytics.threatIntel.common.TIFState;
import org.opensearch.securityanalytics.threatIntel.common.TIFExecutor;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameterService;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobTask;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobUpdateService;
import org.opensearch.tasks.Task;
import org.opensearch.tasks.TaskListener;
import org.opensearch.test.client.NoOpNodeClient;
import org.opensearch.test.rest.RestActionTestCase;
import org.opensearch.threadpool.ThreadPool;

public abstract class ThreatIntelTestCase extends RestActionTestCase {
    @Mock
    protected ClusterService clusterService;
    @Mock
    protected TIFJobUpdateService datasourceUpdateService;
    @Mock
    protected TIFJobParameterService datasourceDao;
    @Mock
    protected TIFExecutor threatIntelExecutor;
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
    protected TIFLockService threatIntelLockService;
    @Mock
    protected RoutingTable routingTable;
    protected IngestMetadata ingestMetadata;
    protected NoOpNodeClient client;
    protected VerifyingClient verifyingClient;
    protected LockService lockService;
    protected ClusterSettings clusterSettings;
    protected Settings settings;
    private AutoCloseable openMocks;

    @Before
    public void prepareIp2GeoTestCase() {
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
    }

    @After
    public void clean() throws Exception {
        openMocks.close();
        client.close();
        verifyingClient.close();
    }

    protected TIFState randomStateExcept(TIFState state) {
        assertNotNull(state);
        return Arrays.stream(TIFState.values())
                .sequential()
                .filter(s -> !s.equals(state))
                .collect(Collectors.toList())
                .get(Randomness.createSecure().nextInt(TIFState.values().length - 2));
    }

    protected TIFState randomState() {
        return Arrays.stream(TIFState.values())
                .sequential()
                .collect(Collectors.toList())
                .get(Randomness.createSecure().nextInt(TIFState.values().length - 1));
    }

    protected TIFJobTask randomTask() {
        return Arrays.stream(TIFJobTask.values())
                .sequential()
                .collect(Collectors.toList())
                .get(Randomness.createSecure().nextInt(TIFJobTask.values().length - 1));
    }

    protected String randomIpAddress() {
        return String.format(
                Locale.ROOT,
                "%d.%d.%d.%d",
                Randomness.get().nextInt(255),
                Randomness.get().nextInt(255),
                Randomness.get().nextInt(255),
                Randomness.get().nextInt(255)
        );
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
    protected TIFJobParameter randomDatasource(final Instant updateStartTime) {
        int validForInDays = 3 + Randomness.get().nextInt(30);
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.setSchedule(
                new IntervalSchedule(
                        updateStartTime.truncatedTo(ChronoUnit.MILLIS),
                        1 + Randomness.get().nextInt(validForInDays - 2),
                        ChronoUnit.DAYS
                )
        );
        datasource.setTask(randomTask());
        datasource.setState(randomState());
        datasource.setCurrentIndex(datasource.newIndexName(UUID.randomUUID().toString()));
        datasource.setIndices(Arrays.asList(ThreatIntelTestHelper.randomLowerCaseString(), ThreatIntelTestHelper.randomLowerCaseString()));
        datasource.getDatabase()
                .setFields(Arrays.asList(ThreatIntelTestHelper.randomLowerCaseString(), ThreatIntelTestHelper.randomLowerCaseString()));
        datasource.getDatabase().setFeedId(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setFeedName(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setFeedFormat(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setEndpoint(String.format(Locale.ROOT, "https://%s.com/manifest.json", ThreatIntelTestHelper.randomLowerCaseString()));
        datasource.getDatabase().setDescription(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setOrganization(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setContained_iocs_field(ThreatIntelTestHelper.randomLowerCaseStringList());
        datasource.getDatabase().setIocCol(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getUpdateStats().setLastSkippedAt(now);
        datasource.getUpdateStats().setLastSucceededAt(now);
        datasource.getUpdateStats().setLastFailedAt(now);
        datasource.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        datasource.setLastUpdateTime(now);
        if (Randomness.get().nextInt() % 2 == 0) {
            datasource.enable();
        } else {
            datasource.disable();
        }
        return datasource;
    }

    protected TIFJobParameter randomDatasource() {
        return randomDatasource(Instant.now());
    }

    protected LockModel randomLockModel() {
        LockModel lockModel = new LockModel(
                ThreatIntelTestHelper.randomLowerCaseString(),
                ThreatIntelTestHelper.randomLowerCaseString(),
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

