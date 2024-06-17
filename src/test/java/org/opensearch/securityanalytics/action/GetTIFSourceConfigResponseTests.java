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
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;
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
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        Source source = new S3Source("bucket", "objectkey", "region", "rolearn");
        List<String> iocTypes = List.of("hash");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
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
                iocTypes
        );

        SAGetTIFSourceConfigResponse response = new SAGetTIFSourceConfigResponse(SaTifSourceConfigDto.getId(), SaTifSourceConfigDto.getVersion(), RestStatus.OK, SaTifSourceConfigDto);
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
        Assert.assertEquals(sourceConfigType, newResponse.getSaTifSourceConfigDto().getFeedType());
        Assert.assertEquals(SaTifSourceConfigDto.getState(), newResponse.getSaTifSourceConfigDto().getState());
        Assert.assertEquals(SaTifSourceConfigDto.getEnabledTime(), newResponse.getSaTifSourceConfigDto().getEnabledTime());
        Assert.assertEquals(SaTifSourceConfigDto.getCreatedAt(), newResponse.getSaTifSourceConfigDto().getCreatedAt());
        Assert.assertEquals(SaTifSourceConfigDto.getLastUpdateTime(), newResponse.getSaTifSourceConfigDto().getLastUpdateTime());
        Assert.assertEquals(SaTifSourceConfigDto.isEnabled(), newResponse.getSaTifSourceConfigDto().isEnabled());
        Assert.assertEquals(SaTifSourceConfigDto.getLastRefreshedTime(), newResponse.getSaTifSourceConfigDto().getLastRefreshedTime());
        Assert.assertEquals(SaTifSourceConfigDto.getLastRefreshedUser(), newResponse.getSaTifSourceConfigDto().getLastRefreshedUser());
        Assert.assertEquals(schedule, newResponse.getSaTifSourceConfigDto().getSchedule());
        Assert.assertEquals(SaTifSourceConfigDto.getCreatedByUser(), newResponse.getSaTifSourceConfigDto().getCreatedByUser());
        Assert.assertTrue(iocTypes.containsAll(newResponse.getSaTifSourceConfigDto().getIocTypes()) &&
                newResponse.getSaTifSourceConfigDto().getIocTypes().containsAll(iocTypes));
    }
}
