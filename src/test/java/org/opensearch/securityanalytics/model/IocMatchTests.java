package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.toJsonString;

public class IocMatchTests extends OpenSearchTestCase {

    public void testIoCMatchAsAStream() throws IOException {
        IocMatch iocMatch = getRandomIoCMatch();
        String jsonString = toJsonString(iocMatch);
        BytesStreamOutput out = new BytesStreamOutput();
        iocMatch.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocMatch newIocMatch = new IocMatch(sin);
        assertEquals(iocMatch.getId(), newIocMatch.getId());
        assertEquals(iocMatch.getIocScanJobId(), newIocMatch.getIocScanJobId());
        assertEquals(iocMatch.getIocScanJobName(), newIocMatch.getIocScanJobName());
        assertEquals(iocMatch.getIocValue(), newIocMatch.getIocValue());
        assertEquals(iocMatch.getIocType(), newIocMatch.getIocType());
        assertEquals(iocMatch.getTimestamp(), newIocMatch.getTimestamp());
        assertEquals(iocMatch.getExecutionId(), newIocMatch.getExecutionId());
        assertTrue(iocMatch.getFeedIds().containsAll(newIocMatch.getFeedIds()));
        assertTrue(iocMatch.getRelatedDocIds().containsAll(newIocMatch.getRelatedDocIds()));
    }

    public void testIoCMatchParse() throws IOException {
        String iocMatchString = "{ \"id\": \"exampleId123\", \"related_doc_ids\": [\"relatedDocId1\", " +
                "\"relatedDocId2\"], \"feed_ids\": [\"feedId1\", \"feedId2\"], \"ioc_scan_job_id\":" +
                " \"scanJob123\", \"ioc_scan_job_name\": \"Example Scan Job\", \"ioc_value\": \"exampleIocValue\", " +
                "\"ioc_type\": \"exampleIocType\", \"timestamp\": 1620912896000, \"execution_id\": \"execution123\" }";
        IocMatch iocMatch = IocMatch.parse((getParser(iocMatchString)));
        BytesStreamOutput out = new BytesStreamOutput();
        iocMatch.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IocMatch newIocMatch = new IocMatch(sin);
        assertEquals(iocMatch.getId(), newIocMatch.getId());
        assertEquals(iocMatch.getIocScanJobId(), newIocMatch.getIocScanJobId());
        assertEquals(iocMatch.getIocScanJobName(), newIocMatch.getIocScanJobName());
        assertEquals(iocMatch.getIocValue(), newIocMatch.getIocValue());
        assertEquals(iocMatch.getIocType(), newIocMatch.getIocType());
        assertEquals(iocMatch.getTimestamp(), newIocMatch.getTimestamp());
        assertEquals(iocMatch.getExecutionId(), newIocMatch.getExecutionId());
        assertTrue(iocMatch.getFeedIds().containsAll(newIocMatch.getFeedIds()));
        assertTrue(iocMatch.getRelatedDocIds().containsAll(newIocMatch.getRelatedDocIds()));
    }

    public XContentParser getParser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;

    }

    private static IocMatch getRandomIoCMatch() {
        return new IocMatch(
                randomAlphaOfLength(10),
                List.of(randomAlphaOfLength(10), randomAlphaOfLength(10)),
                List.of(randomAlphaOfLength(10), randomAlphaOfLength(10)),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                randomAlphaOfLength(10),
                Instant.now(),
                randomAlphaOfLength(10));
    }


}
