/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class GetIndexMappingsRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        GetIndexMappingsRequest getIndexMappingsRequest = new GetIndexMappingsRequest("my_index");
        getIndexMappingsRequest.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        GetIndexMappingsRequest newReq = new GetIndexMappingsRequest(sin);

        assertEquals("my_index", newReq.getIndexName());
    }

    public void testParse() throws IOException {
        XContentParser parser = createParser(JsonXContent.jsonXContent, "{ \"index_name\": \"my_index\" }");
        GetIndexMappingsRequest getIndexMappingsRequest = GetIndexMappingsRequest.parse(parser);
        assertEquals(getIndexMappingsRequest.getIndexName(), "my_index");
    }

    public void testValidate() {
        GetIndexMappingsRequest getIndexMappingsRequest = new GetIndexMappingsRequest("myIndex");
        ActionRequestValidationException e = getIndexMappingsRequest.validate();
        assertNull(e);

        getIndexMappingsRequest = new GetIndexMappingsRequest("");
        e = getIndexMappingsRequest.validate();
        assertNotNull(e);
    }
}
