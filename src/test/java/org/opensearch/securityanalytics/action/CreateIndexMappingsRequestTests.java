/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

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

        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow", null);
        req.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        CreateIndexMappingsRequest newReq = new CreateIndexMappingsRequest(sin);

        assertEquals("my_index", newReq.getIndexName());
        assertEquals("netflow", newReq.getRuleTopic());
    }

    public void testValidate() {
        CreateIndexMappingsRequest req = new CreateIndexMappingsRequest("my_index", "netflow", null);
        ActionRequestValidationException e = req.validate();
        assertNull(e);

        req = new CreateIndexMappingsRequest("", "", null);
        e = req.validate();
        assertNotNull(e);
    }

}
