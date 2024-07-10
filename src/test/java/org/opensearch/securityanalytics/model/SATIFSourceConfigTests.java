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
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.randomSATIFSourceConfig;

public class SATIFSourceConfigTests extends OpenSearchTestCase {

    public void testAsStream() throws IOException {
        SATIFSourceConfig saTifSourceConfig = randomSATIFSourceConfig();
        BytesStreamOutput out = new BytesStreamOutput();
        saTifSourceConfig.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SATIFSourceConfig newSaTifSourceConfig = new SATIFSourceConfig(sin);
        assertEqualsSaTifSourceConfigs(saTifSourceConfig, newSaTifSourceConfig);
    }

    public void testParseFunction() throws IOException {
        SATIFSourceConfig saTifSourceConfig = randomSATIFSourceConfig();
        String json = toJsonString(saTifSourceConfig);
        SATIFSourceConfig newSaTifSourceConfig = SATIFSourceConfig.parse(getParser(json), saTifSourceConfig.getId(), null);
        assertEqualsSaTifSourceConfigs(saTifSourceConfig, newSaTifSourceConfig);
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }
    private String toJsonString(SATIFSourceConfig saTifSourceConfig) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = saTifSourceConfig.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    private void assertEqualsSaTifSourceConfigs(SATIFSourceConfig saTifSourceConfig, SATIFSourceConfig newSaTifSourceConfig) {
        assertEquals(saTifSourceConfig.getId(), newSaTifSourceConfig.getId());
        assertEquals(saTifSourceConfig.getVersion(), newSaTifSourceConfig.getVersion());
        assertEquals(saTifSourceConfig.getName(), newSaTifSourceConfig.getName());
        assertEquals(saTifSourceConfig.getFormat(), newSaTifSourceConfig.getFormat());
        assertEquals(saTifSourceConfig.getType(), newSaTifSourceConfig.getType());
        assertEquals(saTifSourceConfig.getDescription(), newSaTifSourceConfig.getDescription());
        assertEquals(saTifSourceConfig.getCreatedByUser(), newSaTifSourceConfig.getCreatedByUser());
        assertEquals(saTifSourceConfig.getCreatedAt().toEpochMilli(), newSaTifSourceConfig.getCreatedAt().toEpochMilli());
        S3Source source = (S3Source)saTifSourceConfig.getSource();
        S3Source newSource = (S3Source)newSaTifSourceConfig.getSource();
        assertEquals(source.getBucketName(), newSource.getBucketName());
        assertEquals(source.getRegion(), newSource.getRegion());
        assertEquals(source.getObjectKey(), newSource.getObjectKey());
        assertEquals(source.getRoleArn(), newSource.getRoleArn());
        assertEquals(saTifSourceConfig.getEnabledTime().toEpochMilli(), newSaTifSourceConfig.getEnabledTime().toEpochMilli());
        assertEquals(saTifSourceConfig.getLastUpdateTime().toEpochMilli(), newSaTifSourceConfig.getLastUpdateTime().toEpochMilli());
        assertEquals(((IntervalSchedule)saTifSourceConfig.getSchedule()).getStartTime().toEpochMilli(), ((IntervalSchedule) newSaTifSourceConfig.getSchedule()).getStartTime().toEpochMilli());
        assertEquals(((IntervalSchedule)saTifSourceConfig.getSchedule()).getInterval(), ((IntervalSchedule)newSaTifSourceConfig.getSchedule()).getInterval());
        assertEquals(((IntervalSchedule)saTifSourceConfig.getSchedule()).getUnit(), ((IntervalSchedule) newSaTifSourceConfig.getSchedule()).getUnit());
        assertEquals(saTifSourceConfig.getState(), newSaTifSourceConfig.getState());
        assertEquals(saTifSourceConfig.getRefreshType(), newSaTifSourceConfig.getRefreshType());
        assertEquals(saTifSourceConfig.getLastRefreshedTime(), newSaTifSourceConfig.getLastRefreshedTime());
        assertEquals(saTifSourceConfig.isEnabled(), newSaTifSourceConfig.isEnabled());
        DefaultIocStoreConfig iocStoreConfig = (DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig();
        DefaultIocStoreConfig newIocStoreConfig = (DefaultIocStoreConfig) newSaTifSourceConfig.getIocStoreConfig();
        assertEquals(iocStoreConfig.getIocToIndexDetails().get(0).getIocType().getType(), newIocStoreConfig.getIocToIndexDetails().get(0).getIocType().getType());
        assertEquals(iocStoreConfig.getIocToIndexDetails().get(0).getIndexPattern(), newIocStoreConfig.getIocToIndexDetails().get(0).getIndexPattern());
        assertEquals(iocStoreConfig.getIocToIndexDetails().get(0).getActiveIndex(), newIocStoreConfig.getIocToIndexDetails().get(0).getActiveIndex());
        assertEquals(saTifSourceConfig.getIocTypes(), newSaTifSourceConfig.getIocTypes());
    }
}