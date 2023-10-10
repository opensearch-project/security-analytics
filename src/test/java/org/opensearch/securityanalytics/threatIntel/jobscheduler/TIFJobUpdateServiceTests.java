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
import java.util.ArrayList;
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
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;


@SuppressForbidden(reason = "unit test")
public class TIFJobUpdateServiceTests extends ThreatIntelTestCase {
    private TIFJobUpdateService datasourceUpdateService;

    @Before
    public void init() {
        datasourceUpdateService = new TIFJobUpdateService(clusterService, tifJobParameterService, threatIntelFeedDataService);
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenHashValueIsSame_thenSkipUpdate() throws IOException {
        List<String> containedIocs = new ArrayList<>();
        containedIocs.add("ip");
        TIFMetadata tifMetadata = new TIFMetadata("id", "url", "name", "org", "desc", "type", containedIocs, "0");

        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setState(TIFJobState.AVAILABLE);

        // Run
        datasourceUpdateService.createThreatIntelFeedData(datasource, mock(Runnable.class));

        // Verify
        assertNotNull(datasource.getUpdateStats().getLastSkippedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(datasource);
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenInvalidData_thenThrowException() throws IOException {
        List<String> containedIocs = new ArrayList<>();
        containedIocs.add("ip");
        TIFMetadata tifMetadata = new TIFMetadata("id", "url", "name", "org", "desc", "type", containedIocs, "0");

        File sampleFile = new File(
                this.getClass().getClassLoader().getResource("threatIntel/sample_invalid_less_than_two_fields.csv").getFile()
        );
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setState(TIFJobState.AVAILABLE);
        // Run
        expectThrows(OpenSearchException.class, () -> datasourceUpdateService.createThreatIntelFeedData(datasource, mock(Runnable.class)));
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenIncompatibleFields_thenThrowException() throws IOException {
        List<String> containedIocs = new ArrayList<>();
        containedIocs.add("ip");
        TIFMetadata tifMetadata = new TIFMetadata("id", "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv", "name", "org", "desc", "type", containedIocs, "0");

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));

        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setState(TIFJobState.AVAILABLE);


        // Run
        expectThrows(OpenSearchException.class, () -> datasourceUpdateService.createThreatIntelFeedData(datasource, mock(Runnable.class)));
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenValidInput_thenSucceed() throws IOException {
        List<String> containedIocs = new ArrayList<>();
        containedIocs.add("ip");
        TIFMetadata tifMetadata = new TIFMetadata("id", "url", "name", "org", "desc", "type", containedIocs, "0");

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));
        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(true);
        when(routingTable.allShards(anyString())).thenReturn(Arrays.asList(shardRouting));

        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setState(TIFJobState.AVAILABLE);

        datasource.getUpdateStats().setLastSucceededAt(null);
        datasource.getUpdateStats().setLastProcessingTimeInMillis(null);

        // Run
        datasourceUpdateService.createThreatIntelFeedData(datasource, mock(Runnable.class));

        // Verify

        assertNotNull(datasource.getUpdateStats().getLastSucceededAt());
        assertNotNull(datasource.getUpdateStats().getLastProcessingTimeInMillis());
        verify(tifJobParameterService, times(2)).updateJobSchedulerParameter(datasource);
        verify(threatIntelFeedDataService).saveThreatIntelFeedDataCSV(eq(datasource.currentIndexName()), isA(String[].class), any(Iterator.class), any(Runnable.class), tifMetadata);
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

    public void testDeleteUnusedIndices_whenValidInput_thenSucceed() {
        String datasourceName = ThreatIntelTestHelper.randomLowerCaseString();
        String indexPrefix = String.format(".threatintel-data.%s.", datasourceName);
        Instant now = Instant.now();
        String currentIndex = indexPrefix + now.toEpochMilli();
        String oldIndex = indexPrefix + now.minusMillis(1).toEpochMilli();
        String lingeringIndex = indexPrefix + now.minusMillis(2).toEpochMilli();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(datasourceName);
        datasource.setCurrentIndex(currentIndex);
        datasource.getIndices().add(currentIndex);
        datasource.getIndices().add(oldIndex);
        datasource.getIndices().add(lingeringIndex);

        when(metadata.hasIndex(currentIndex)).thenReturn(true);
        when(metadata.hasIndex(oldIndex)).thenReturn(true);
        when(metadata.hasIndex(lingeringIndex)).thenReturn(false);

        datasourceUpdateService.deleteAllTifdIndices(datasource);

        assertEquals(0, datasource.getIndices().size());
//        assertEquals(currentIndex, datasource.getIndices().get(0)); //TODO: check this
        verify(tifJobParameterService).updateJobSchedulerParameter(datasource);
        verify(threatIntelFeedDataService).deleteThreatIntelDataIndex(oldIndex);
    }

    public void testUpdateDatasource_whenNoChange_thenNoUpdate() {
        TIFJobParameter datasource = randomTifJobParameter();

        // Run
        datasourceUpdateService.updateJobSchedulerParameter(datasource, datasource.getSchedule(), datasource.getTask());

        // Verify
        verify(tifJobParameterService, never()).updateJobSchedulerParameter(any());
    }

    public void testUpdateDatasource_whenChange_thenUpdate() {
        TIFJobParameter datasource = randomTifJobParameter();
        datasource.setTask(TIFJobTask.ALL);

        // Run
        datasourceUpdateService.updateJobSchedulerParameter(
                datasource,
                new IntervalSchedule(Instant.now(), datasource.getSchedule().getInterval() + 1, ChronoUnit.DAYS),
                datasource.getTask()
        );
        datasourceUpdateService.updateJobSchedulerParameter(datasource, datasource.getSchedule(), TIFJobTask.DELETE_UNUSED_INDICES);

        // Verify
        verify(tifJobParameterService, times(2)).updateJobSchedulerParameter(any());
    }
}
