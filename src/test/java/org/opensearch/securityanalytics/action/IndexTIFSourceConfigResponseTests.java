package org.opensearch.securityanalytics.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class IndexTIFSourceConfigResponseTests extends OpenSearchTestCase {

    private static final Logger log = LogManager.getLogger(IndexTIFSourceConfigResponseTests.class);

    public void testIndexTIFSourceConfigPostResponse() throws IOException {
        String feedName = "feed_Name";
        String feedFormat = "STIX";
        FeedType feedType = FeedType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        Source source = new S3Source("bucket", "objectkey", "region", "rolearn");
        List<String> iocTypes = List.of("hash");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                feedType,
                null,
                null,
                Instant.now(),
                source,
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