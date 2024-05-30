package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class IndexTIFSourceConfigResponseTests extends OpenSearchTestCase {

    public void testIndexTIFSourceConfigPostResponse() throws IOException {
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
                null,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                true,
                null,
                iocTypes
        );

        SAIndexTIFSourceConfigResponse response = new SAIndexTIFSourceConfigResponse(SaTifSourceConfigDto.getId(), SaTifSourceConfigDto.getVersion(), RestStatus.OK, SaTifSourceConfigDto);
        Assert.assertNotNull(response);

        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SAIndexTIFSourceConfigResponse newResponse = new SAIndexTIFSourceConfigResponse(sin);

        Assert.assertEquals(SaTifSourceConfigDto.getId(), newResponse.getTIFConfigId());
        Assert.assertEquals(SaTifSourceConfigDto.getVersion(), newResponse.getVersion());
        Assert.assertEquals(RestStatus.OK, newResponse.getStatus());
        Assert.assertNotNull(newResponse.getTIFConfigDto());
        Assert.assertEquals(feedName, newResponse.getTIFConfigDto().getName());
        Assert.assertEquals(feedFormat, newResponse.getTIFConfigDto().getFeedFormat());
        Assert.assertEquals(feedType, newResponse.getTIFConfigDto().getFeedType());
        Assert.assertEquals(schedule, newResponse.getTIFConfigDto().getSchedule());
        Assert.assertTrue(iocTypes.containsAll(newResponse.getTIFConfigDto().getIocTypes()) &&
                newResponse.getTIFConfigDto().getIocTypes().containsAll(iocTypes));
    }
}