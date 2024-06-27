package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.IocWithFeeds;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.toJsonString;

public class IocFindingTests extends OpenSearchTestCase {

    public void testIoCMatchAsAStream() throws IOException {
        IocFinding iocFinding = getRandomIoCMatch();
        String jsonString = toJsonString(iocFinding);
        BytesStreamOutput out = new BytesStreamOutput();
        iocFinding.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocFinding newIocFinding = new IocFinding(sin);
        assertEquals(iocFinding.getId(), newIocFinding.getId());
        assertEquals(iocFinding.getMonitorId(), newIocFinding.getMonitorId());
        assertEquals(iocFinding.getMonitorName(), newIocFinding.getMonitorName());
        assertEquals(iocFinding.getIocValue(), newIocFinding.getIocValue());
        assertEquals(iocFinding.getIocType(), newIocFinding.getIocType());
        assertEquals(iocFinding.getTimestamp(), newIocFinding.getTimestamp());
        assertEquals(iocFinding.getExecutionId(), newIocFinding.getExecutionId());
        assertTrue(iocFinding.getFeedIds().containsAll(newIocFinding.getFeedIds()));
        assertTrue(iocFinding.getRelatedDocIds().containsAll(newIocFinding.getRelatedDocIds()));
    }

    public void testIoCMatchParse() throws IOException {
        String iocMatchString = "{ \"id\": \"exampleId123\", \"related_doc_ids\": [\"relatedDocId1\", " +
                "\"relatedDocId2\"], \"feed_ids\": [\"feedId1\", \"feedId2\"], \"ioc_scan_job_id\":" +
                " \"scanJob123\", \"ioc_scan_job_name\": \"Example Scan Job\", \"ioc_value\": \"exampleIocValue\", " +
                "\"ioc_type\": \"exampleIocType\", \"timestamp\": 1620912896000, \"execution_id\": \"execution123\" }";
        IocFinding iocFinding = IocFinding.parse((getParser(iocMatchString)));
        BytesStreamOutput out = new BytesStreamOutput();
        iocFinding.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocFinding newIocFinding = new IocFinding(sin);
        assertEquals(iocFinding.getId(), newIocFinding.getId());
        assertEquals(iocFinding.getMonitorId(), newIocFinding.getMonitorId());
        assertEquals(iocFinding.getMonitorName(), newIocFinding.getMonitorName());
        assertEquals(iocFinding.getIocValue(), newIocFinding.getIocValue());
        assertEquals(iocFinding.getIocType(), newIocFinding.getIocType());
        assertEquals(iocFinding.getTimestamp(), newIocFinding.getTimestamp());
        assertEquals(iocFinding.getExecutionId(), newIocFinding.getExecutionId());
        assertTrue(iocFinding.getFeedIds().containsAll(newIocFinding.getFeedIds()));
        assertTrue(iocFinding.getRelatedDocIds().containsAll(newIocFinding.getRelatedDocIds()));
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }

    private static IocFinding getRandomIoCMatch() {
        return new IocFinding(
                randomAlphaOfLength(10),
                List.of(randomAlphaOfLength(10), randomAlphaOfLength(10)),
                List.of(new IocWithFeeds(randomAlphaOfLength(10), randomAlphaOfLength(10), randomAlphaOfLength(10))),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                Instant.now(),
                randomAlphaOfLength(10));
    }


}
