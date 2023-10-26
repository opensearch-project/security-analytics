/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SuppressForbidden(reason = "unit test")
public class TIFJobUpdateServiceTests extends ThreatIntelTestCase {

    private TIFJobUpdateService tifJobUpdateService1;

    @Before
    public void init() {
        tifJobUpdateService1 = new TIFJobUpdateService(clusterService, tifJobParameterService, threatIntelFeedDataService, builtInTIFMetadataLoader);
    }

    public void testUpdateOrCreateThreatIntelFeedData_whenValidInput_thenSucceed() throws IOException {

        ShardRouting shardRouting = mock(ShardRouting.class);
        when(shardRouting.started()).thenReturn(true);
        when(routingTable.allShards(anyString())).thenReturn(Arrays.asList(shardRouting));

        TIFJobParameter tifJobParameter = new TIFJobParameter();
        tifJobParameter.setState(TIFJobState.AVAILABLE);

        tifJobParameter.getUpdateStats().setLastSucceededAt(null);
        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(null);

        // Run
        List<String> newFeeds = tifJobUpdateService1.createThreatIntelFeedData(tifJobParameter, mock(Runnable.class));

        // Verify feeds
        assertNotNull(newFeeds);
    }

}
