/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class CreateIndexMappingsRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow", true);
        req.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        CreateIndexMappingsRequest newReq = new CreateIndexMappingsRequest(sin);

        assertEquals("my_index", newReq.getIndexName());
        assertEquals("netflow", newReq.getRuleTopic());
        assertTrue(req.getPartial());
    }

    public void testParse() throws IOException {

        String jsonPayload =
                "{" +
                "   \"index_name\":\"my_index\"," +
                "   \"rule_topic\":\"netflow\"," +
                "   \"partial\":true" +
                "}";

        XContentParser parser = createParser(JsonXContent.jsonXContent, jsonPayload);
        CreateIndexMappingsRequest req = CreateIndexMappingsRequest.parse(parser);
        assertEquals("my_index", req.getIndexName());
        assertEquals("netflow", req.getRuleTopic());
        assertTrue(req.getPartial());
    }

    public void testValidate() {
        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow", true);
        ActionRequestValidationException e = req.validate();
        assertNull(e);

        req = new CreateIndexMappingsRequest("", "", false);
        e = req.validate();
        assertNotNull(e);
    }

}
