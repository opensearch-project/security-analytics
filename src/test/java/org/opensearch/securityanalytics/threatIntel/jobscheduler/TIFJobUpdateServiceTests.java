/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.commons.csv.CSVParser;
import org.junit.Before;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedParser;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;



@SuppressForbidden(reason = "unit test")
public class TIFJobUpdateServiceTests extends ThreatIntelTestCase {
    private TIFJobUpdateService tifJobUpdateService1;
    @Before
    public void init() {
        tifJobUpdateService1 = new TIFJobUpdateService(clusterService, tifJobParameterService, threatIntelFeedDataService);
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenValidInput_thenSucceed() throws IOException {
        List<String> containedIocs = new ArrayList<>();
        containedIocs.add("ip");
        TIFMetadata tifMetadata = new TIFMetadata("id", "https://reputation.alienvault.com/reputation.generic", "name", "org", "desc", "type", containedIocs, 0, false);

        File sampleFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.csv").getFile());
        CSVParser csvParser = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata);
//        when(ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata)).thenReturn(CSVParser.parse(sampleFile, StandardCharsets.UTF_8, CSVFormat.RFC4180));
        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(true);
        when(routingTable.allShards(anyString())).thenReturn(Arrays.asList(shardRouting));

        TIFJobParameter tifJobParameter = new TIFJobParameter();
        tifJobParameter.setState(TIFJobState.AVAILABLE);

        tifJobParameter.getUpdateStats().setLastSucceededAt(null);
        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(null);

        // Run
        tifJobUpdateService1.createThreatIntelFeedData(tifJobParameter, mock(Runnable.class));

        // Verify

        assertNotNull(tifJobParameter.getUpdateStats().getLastSucceededAt());
        assertNotNull(tifJobParameter.getUpdateStats().getLastProcessingTimeInMillis());
        verify(tifJobParameterService, times(2)).updateJobSchedulerParameter(tifJobParameter);
        verify(threatIntelFeedDataService).parseAndSaveThreatIntelFeedDataCSV(eq(tifJobParameter.getName()), any(Iterator.class), any(Runnable.class), tifMetadata);
    }

}
