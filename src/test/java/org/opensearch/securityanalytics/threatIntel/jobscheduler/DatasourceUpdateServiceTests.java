/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.junit.Before;
import org.opensearch.OpenSearchException;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedParser;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceTask;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceUpdateService;


@SuppressForbidden(reason = "unit test")
public class DatasourceUpdateServiceTests extends ThreatIntelTestCase {
    private DatasourceUpdateService datasourceUpdateService;

    @Before
    public void init() {
        datasourceUpdateService = new DatasourceUpdateService(clusterService, datasourceDao, threatIntelFeedDataService);
    }

    public void testUpdateOrCreateGeoIpData_whenHashValueIsSame_thenSkipUpdate() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        DatasourceManifest manifest = DatasourceManifest.Builder.build(manifestFile.toURI().toURL());

        Datasource datasource = new Datasource();
        datasource.setState(DatasourceState.AVAILABLE);
        datasource.getDatabase().setFeedId(manifest.getFeedId());
        datasource.getDatabase().setFeedName(manifest.getName());
        datasource.getDatabase().setFeedFormat(manifest.getFeedType());
        datasource.getDatabase().setEndpoint(manifest.getUrl());
        datasource.getDatabase().setOrganization(manifest.getOrganization());
        datasource.getDatabase().setDescription(manifest.getDescription());
        datasource.getDatabase().setContained_iocs_field(manifest.getContainedIocs());
        datasource.getDatabase().setIocCol(manifest.getIocCol());

        datasource.getDatabase().setFields(Arrays.asList("ip", "region"));

        // Run
        datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, mock(Runnable.class));

        // Verify
        assertNotNull(datasource.getUpdateStats().getLastSkippedAt());
        verify(datasourceDao).updateDatasource(datasource);
    }

    public void testUpdateOrCreateGeoIpData_whenInvalidData_thenThrowException() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        DatasourceManifest manifest = DatasourceManifest.Builder.build(manifestFile.toURI().toURL());

        File sampleFile = new File(
                this.getClass().getClassLoader().getResource("threatIntel/sample_invalid_less_than_two_fields.csv").getFile()
        );
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(any())).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        Datasource datasource = new Datasource();
        datasource.setState(DatasourceState.AVAILABLE);
        datasource.getDatabase().setFeedId(manifest.getFeedId());
        datasource.getDatabase().setFeedName(manifest.getName());
        datasource.getDatabase().setFeedFormat(manifest.getFeedType());
        datasource.getDatabase().setEndpoint(manifest.getUrl());
        datasource.getDatabase().setOrganization(manifest.getOrganization());
        datasource.getDatabase().setDescription(manifest.getDescription());
        datasource.getDatabase().setContained_iocs_field(manifest.getContainedIocs());
        datasource.getDatabase().setIocCol(manifest.getIocCol());

        datasource.getDatabase().setFields(Arrays.asList("ip", "region"));

        // Run
        expectThrows(OpenSearchException.class, () -> datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, mock(Runnable.class)));
    }

    public void testUpdateOrCreateGeoIpData_whenIncompatibleFields_thenThrowException() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        DatasourceManifest manifest = DatasourceManifest.Builder.build(manifestFile.toURI().toURL());

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(any())).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        Datasource datasource = new Datasource();
        datasource.setState(DatasourceState.AVAILABLE);
        datasource.getDatabase().setFeedId(manifest.getFeedId());
        datasource.getDatabase().setFeedName(manifest.getName());
        datasource.getDatabase().setFeedFormat(manifest.getFeedType());
        datasource.getDatabase().setEndpoint(manifest.getUrl());
        datasource.getDatabase().setOrganization(manifest.getOrganization());
        datasource.getDatabase().setDescription(manifest.getDescription());
        datasource.getDatabase().setContained_iocs_field(manifest.getContainedIocs());
        datasource.getDatabase().setIocCol(manifest.getIocCol());

        datasource.getDatabase().setFields(Arrays.asList("ip", "region"));

        // Run
        expectThrows(OpenSearchException.class, () -> datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, mock(Runnable.class)));
    }

    public void testUpdateOrCreateGeoIpData_whenValidInput_thenSucceed() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        DatasourceManifest manifest = DatasourceManifest.Builder.build(manifestFile.toURI().toURL());

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(any())).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));
        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(true);
        when(routingTable.allShards(anyString())).thenReturn(Arrays.asList(shardRouting));

        Datasource datasource = new Datasource();
        datasource.setState(DatasourceState.AVAILABLE);
        datasource.getDatabase().setFeedId(manifest.getFeedId());
        datasource.getDatabase().setFeedName(manifest.getName());
        datasource.getDatabase().setFeedFormat(manifest.getFeedType());
        datasource.getDatabase().setEndpoint(manifest.getUrl());
        datasource.getDatabase().setOrganization(manifest.getOrganization());
        datasource.getDatabase().setDescription(manifest.getDescription());
        datasource.getDatabase().setContained_iocs_field(manifest.getContainedIocs());
        datasource.getDatabase().setIocCol(manifest.getIocCol());

//        datasource.getDatabase().setFields(Arrays.asList("country_name"));
//        datasource.setEndpoint(manifestFile.toURI().toURL().toExternalForm());
        datasource.getUpdateStats().setLastSucceededAt(null);
        datasource.getUpdateStats().setLastProcessingTimeInMillis(null);

        // Run
        datasourceUpdateService.updateOrCreateThreatIntelFeedData(datasource, mock(Runnable.class));

        // Verify
        assertEquals(manifest.getFeedId(), datasource.getDatabase().getFeedId());
        assertEquals(manifest.getName(), datasource.getDatabase().getFeedName());
        assertEquals(manifest.getFeedType(), datasource.getDatabase().getFeedFormat());
        assertEquals(manifest.getUrl(), datasource.getDatabase().getEndpoint());
        assertEquals(manifest.getOrganization(), datasource.getDatabase().getOrganization());
        assertEquals(manifest.getDescription(), datasource.getDatabase().getDescription());
        assertEquals(manifest.getOrganization(), datasource.getDatabase().getOrganization());
        assertEquals(manifest.getContainedIocs(), datasource.getDatabase().getContained_iocs_field());
        assertEquals(manifest.getIocCol(), datasource.getDatabase().getIocCol());

        assertNotNull(datasource.getUpdateStats().getLastSucceededAt());
        assertNotNull(datasource.getUpdateStats().getLastProcessingTimeInMillis());
        verify(datasourceDao, times(2)).updateDatasource(datasource);
        verify(threatIntelFeedDataService).saveThreatIntelFeedDataCSV(eq(datasource.currentIndexName()), isA(String[].class), any(Iterator.class), any(Runnable.class), manifest);
    }

    public void testWaitUntilAllShardsStarted_whenTimedOut_thenThrowException() {
        String indexName = ThreatIntelTestHelper.randomLowerCaseString();
        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(false);
        when(routingTable.allShards(indexName)).thenReturn(Arrays.asList(shardRouting));

        // Run
        Exception e = expectThrows(OpenSearchException.class, () -> datasourceUpdateService.waitUntilAllShardsStarted(indexName, 10));

        // Verify
        assertTrue(e.getMessage().contains("did not complete"));
    }

    public void testWaitUntilAllShardsStarted_whenInterrupted_thenThrowException() {
        String indexName = ThreatIntelTestHelper.randomLowerCaseString();
        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(false);
        when(routingTable.allShards(indexName)).thenReturn(Arrays.asList(shardRouting));

        // Run
        Thread.currentThread().interrupt();
        Exception e = expectThrows(RuntimeException.class, () -> datasourceUpdateService.waitUntilAllShardsStarted(indexName, 10));

        // Verify
        assertEquals(InterruptedException.class, e.getCause().getClass());
    }

    public void testGetHeaderFields_whenValidInput_thenReturnCorrectValue() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(any())).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        // Run
        assertEquals(Arrays.asList("country_name"), datasourceUpdateService.getHeaderFields(manifestFile.toURI().toURL().toExternalForm()));
    }

    public void testDeleteUnusedIndices_whenValidInput_thenSucceed() {
        String datasourceName = ThreatIntelTestHelper.randomLowerCaseString();
        String indexPrefix = String.format(".threatintel-data.%s.", datasourceName);
        Instant now = Instant.now();
        String currentIndex = indexPrefix + now.toEpochMilli();
        String oldIndex = indexPrefix + now.minusMillis(1).toEpochMilli();
        String lingeringIndex = indexPrefix + now.minusMillis(2).toEpochMilli();
        Datasource datasource = new Datasource();
        datasource.setName(datasourceName);
        datasource.setCurrentIndex(currentIndex);
        datasource.getIndices().add(currentIndex);
        datasource.getIndices().add(oldIndex);
        datasource.getIndices().add(lingeringIndex);

        when(metadata.hasIndex(currentIndex)).thenReturn(true);
        when(metadata.hasIndex(oldIndex)).thenReturn(true);
        when(metadata.hasIndex(lingeringIndex)).thenReturn(false);

        datasourceUpdateService.deleteUnusedIndices(datasource);

        assertEquals(1, datasource.getIndices().size());
        assertEquals(currentIndex, datasource.getIndices().get(0));
        verify(datasourceDao).updateDatasource(datasource);
        verify(threatIntelFeedDataService).deleteThreatIntelDataIndex(oldIndex);
    }

    public void testUpdateDatasource_whenNoChange_thenNoUpdate() {
        Datasource datasource = randomDatasource();

        // Run
        datasourceUpdateService.updateDatasource(datasource, datasource.getSchedule(), datasource.getTask());

        // Verify
        verify(datasourceDao, never()).updateDatasource(any());
    }

    public void testUpdateDatasource_whenChange_thenUpdate() {
        Datasource datasource = randomDatasource();
        datasource.setTask(DatasourceTask.ALL);

        // Run
        datasourceUpdateService.updateDatasource(
                datasource,
                new IntervalSchedule(Instant.now(), datasource.getSchedule().getInterval() + 1, ChronoUnit.DAYS),
                datasource.getTask()
        );
        datasourceUpdateService.updateDatasource(datasource, datasource.getSchedule(), DatasourceTask.DELETE_UNUSED_INDICES);

        // Verify
        verify(datasourceDao, times(2)).updateDatasource(any());
    }

    public void testGetHeaderFields_whenValidInput_thenSucceed() throws IOException {
        File manifestFile = new File(this.getClass().getClassLoader().getResource("threatIntel/manifest.json").getFile());
        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(any())).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        // Run
        List<String> fields = datasourceUpdateService.getHeaderFields(manifestFile.toURI().toURL().toExternalForm());

        // Verify
        List<String> expectedFields = Arrays.asList("country_name");
        assertEquals(expectedFields, fields);
    }
}
