package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.randomSATIFSourceConfigDto;

public class SATIFSourceConfigDtoTests extends OpenSearchTestCase {

    public void testAsStream() throws IOException {
        SATIFSourceConfigDto saTifSourceConfigDto = randomSATIFSourceConfigDto();
        BytesStreamOutput out = new BytesStreamOutput();
        saTifSourceConfigDto.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SATIFSourceConfigDto newSaTifSourceConfigDto = new SATIFSourceConfigDto(sin);
        assertEqualsSaTifSourceConfigDtos(saTifSourceConfigDto, newSaTifSourceConfigDto);
    }

    public void testParseFunction() throws IOException {
        SATIFSourceConfigDto saTifSourceConfigDto = randomSATIFSourceConfigDto();
        String json = toJsonString(saTifSourceConfigDto);
        SATIFSourceConfigDto newSaTifSourceConfigDto = SATIFSourceConfigDto.parse(getParser(json), saTifSourceConfigDto.getId(), null);
        assertEqualsSaTifSourceConfigDtos(saTifSourceConfigDto, newSaTifSourceConfigDto);
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }
    private String toJsonString(SATIFSourceConfigDto saTifSourceConfigDto) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = saTifSourceConfigDto.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    private void assertEqualsSaTifSourceConfigDtos(SATIFSourceConfigDto saTifSourceConfigDto, SATIFSourceConfigDto newSaTifSourceConfigDto) {
        assertEquals(saTifSourceConfigDto.getId(), newSaTifSourceConfigDto.getId());
        assertEquals(saTifSourceConfigDto.getVersion(), newSaTifSourceConfigDto.getVersion());
        assertEquals(saTifSourceConfigDto.getName(), newSaTifSourceConfigDto.getName());
        assertEquals(saTifSourceConfigDto.getFormat(), newSaTifSourceConfigDto.getFormat());
        assertEquals(saTifSourceConfigDto.getType(), newSaTifSourceConfigDto.getType());
        assertEquals(saTifSourceConfigDto.getDescription(), newSaTifSourceConfigDto.getDescription());
        assertEquals(saTifSourceConfigDto.getCreatedByUser(), newSaTifSourceConfigDto.getCreatedByUser());
        assertEquals(saTifSourceConfigDto.getCreatedAt().toEpochMilli(), newSaTifSourceConfigDto.getCreatedAt().toEpochMilli());
        S3Source source = (S3Source)saTifSourceConfigDto.getSource();
        S3Source newSource = (S3Source)newSaTifSourceConfigDto.getSource();
        assertEquals(source.getBucketName(), newSource.getBucketName());
        assertEquals(source.getRegion(), newSource.getRegion());
        assertEquals(source.getObjectKey(), newSource.getObjectKey());
        assertEquals(source.getRoleArn(), newSource.getRoleArn());
        assertEquals(saTifSourceConfigDto.getEnabledTime().toEpochMilli(), newSaTifSourceConfigDto.getEnabledTime().toEpochMilli());
        assertEquals(saTifSourceConfigDto.getLastUpdateTime().toEpochMilli(), newSaTifSourceConfigDto.getLastUpdateTime().toEpochMilli());
        assertEquals(((IntervalSchedule)saTifSourceConfigDto.getSchedule()).getStartTime().toEpochMilli(), ((IntervalSchedule)newSaTifSourceConfigDto.getSchedule()).getStartTime().toEpochMilli());
        assertEquals(((IntervalSchedule)saTifSourceConfigDto.getSchedule()).getInterval(), ((IntervalSchedule)newSaTifSourceConfigDto.getSchedule()).getInterval());
        assertEquals(((IntervalSchedule)saTifSourceConfigDto.getSchedule()).getUnit(), ((IntervalSchedule)newSaTifSourceConfigDto.getSchedule()).getUnit());
        assertEquals(saTifSourceConfigDto.getState(), newSaTifSourceConfigDto.getState());
        assertEquals(saTifSourceConfigDto.getRefreshType(), newSaTifSourceConfigDto.getRefreshType());
        assertEquals(saTifSourceConfigDto.getLastRefreshedTime(), newSaTifSourceConfigDto.getLastRefreshedTime());
        assertEquals(saTifSourceConfigDto.isEnabled(), newSaTifSourceConfigDto.isEnabled());
        assertEquals(saTifSourceConfigDto.getIocTypes(), newSaTifSourceConfigDto.getIocTypes());
    }
}