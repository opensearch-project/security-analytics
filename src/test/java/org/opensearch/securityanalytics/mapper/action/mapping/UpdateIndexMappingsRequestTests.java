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
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class UpdateIndexMappingsRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        UpdateIndexMappingsRequest req = new UpdateIndexMappingsRequest("my_index", "fieldA", "fieldA_alias");
        req.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        UpdateIndexMappingsRequest newReq = new UpdateIndexMappingsRequest(sin);

        assertEquals("my_index", newReq.getIndexName());
        assertEquals("fieldA", newReq.getField());
        assertEquals("fieldA_alias", newReq.getAlias());
    }

    public void testParse() throws IOException {

        String jsonPayload =
                "{" +
                "   \"index_name\":\"my_index\"," +
                "   \"field\":\"fieldA\"," +
                "   \"alias\":\"fieldA_alias\"" +
                "}";

        XContentParser parser = createParser(JsonXContent.jsonXContent, jsonPayload);
        UpdateIndexMappingsRequest req = UpdateIndexMappingsRequest.parse(parser);
        assertEquals(req.getIndexName(), "my_index");
        assertEquals(req.getField(), "fieldA");
        assertEquals(req.getAlias(), "fieldA_alias");
    }

    public void testValidate() {
        UpdateIndexMappingsRequest req = new UpdateIndexMappingsRequest("my_index", "fieldA", "fieldA_alias");
        ActionRequestValidationException e = req.validate();
        assertNull(e);

        req = new UpdateIndexMappingsRequest("", "", "");
        e = req.validate();
        assertNotNull(e);
    }

}
