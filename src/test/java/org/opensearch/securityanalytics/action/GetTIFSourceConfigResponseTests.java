/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class GetTIFSourceConfigResponseTests extends OpenSearchTestCase {
    private static final Logger log = LogManager.getLogger(GetTIFSourceConfigResponseTests.class);

    public void testStreamInOut() throws IOException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        FeedType feedType = FeedType.INTERNAL;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        List<String> iocTypes = List.of("ip", "dns");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                feedType,
                null,
                Instant.now(),
                null,
                Instant.now(),
                schedule,
                null,
                null,
                Instant.now(),
                null,
                false,
                null,
                iocTypes
        );

        SAGetTIFSourceConfigResponse response = new SAGetTIFSourceConfigResponse(SaTifSourceConfigDto.getId(), SaTifSourceConfigDto.getVersion(), RestStatus.OK, SaTifSourceConfigDto);
        log.error(SaTifSourceConfigDto.getLastUpdateTime());
        Assert.assertNotNull(response);

        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SAGetTIFSourceConfigResponse newResponse = new SAGetTIFSourceConfigResponse(sin);

        Assert.assertEquals(SaTifSourceConfigDto.getId(), newResponse.getId());
        Assert.assertEquals(SaTifSourceConfigDto.getVersion(), newResponse.getVersion());
        Assert.assertEquals(RestStatus.OK, newResponse.getStatus());
        Assert.assertNotNull(newResponse.getSaTifSourceConfigDto());
        Assert.assertEquals(feedName, newResponse.getSaTifSourceConfigDto().getName());
        Assert.assertEquals(feedFormat, newResponse.getSaTifSourceConfigDto().getFeedFormat());
        Assert.assertEquals(feedType, newResponse.getSaTifSourceConfigDto().getFeedType());
        Assert.assertEquals(SaTifSourceConfigDto.getState(), newResponse.getSaTifSourceConfigDto().getState());
        Assert.assertEquals(SaTifSourceConfigDto.getEnabledTime(), newResponse.getSaTifSourceConfigDto().getEnabledTime());
        Assert.assertEquals(SaTifSourceConfigDto.getCreatedAt(), newResponse.getSaTifSourceConfigDto().getCreatedAt());
        Assert.assertEquals(SaTifSourceConfigDto.getLastUpdateTime(), newResponse.getSaTifSourceConfigDto().getLastUpdateTime());
        Assert.assertEquals(SaTifSourceConfigDto.isEnabled(), newResponse.getSaTifSourceConfigDto().isEnabled());
        Assert.assertEquals(SaTifSourceConfigDto.getLastRefreshedTime(), newResponse.getSaTifSourceConfigDto().getLastRefreshedTime());
        Assert.assertEquals(SaTifSourceConfigDto.getLastRefreshedUser(), newResponse.getSaTifSourceConfigDto().getLastRefreshedUser());
        Assert.assertEquals(schedule, newResponse.getSaTifSourceConfigDto().getSchedule());
        Assert.assertEquals(SaTifSourceConfigDto.getCreatedByUser(), newResponse.getSaTifSourceConfigDto().getCreatedByUser());
        Assert.assertEquals(SaTifSourceConfigDto.getIocMapStore(), newResponse.getSaTifSourceConfigDto().getIocMapStore());
        Assert.assertTrue(iocTypes.containsAll(newResponse.getSaTifSourceConfigDto().getIocTypes()) &&
                newResponse.getSaTifSourceConfigDto().getIocTypes().containsAll(iocTypes));
    }
}
