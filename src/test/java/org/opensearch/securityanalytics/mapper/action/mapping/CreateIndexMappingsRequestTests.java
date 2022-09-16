/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.mapper.model.CreateIndexMappingsRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class CreateIndexMappingsRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow");
        req.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        CreateIndexMappingsRequest newReq = new CreateIndexMappingsRequest(sin);

        assertEquals("my_index", newReq.getIndexName());
        assertEquals("netflow", newReq.getRuleTopic());
    }

    public void testParse() throws IOException {

        String jsonPayload =
                "{" +
                "   \"indexName\":\"my_index\"," +
                "   \"ruleTopic\":\"netflow\"" +
                "}";

        XContentParser parser = createParser(JsonXContent.jsonXContent, jsonPayload);
        CreateIndexMappingsRequest req = CreateIndexMappingsRequest.parse(parser);
        assertEquals(req.getIndexName(), "my_index");
        assertEquals(req.getRuleTopic(), "netflow");
    }

    public void testValidate() {
        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow");
        ActionRequestValidationException e = req.validate();
        assertNull(e);

        req = new CreateIndexMappingsRequest("", "");
        e = req.validate();
        assertNotNull(e);
    }

}
