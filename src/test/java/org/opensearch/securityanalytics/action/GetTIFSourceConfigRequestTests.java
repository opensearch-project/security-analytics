/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.UUIDs;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class GetTIFSourceConfigRequestTests extends OpenSearchTestCase {
    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();
        String id = UUIDs.base64UUID();
        Long version = 1L;

        SAGetTIFSourceConfigRequest request = new SAGetTIFSourceConfigRequest(id, version);
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SAGetTIFSourceConfigRequest newReq = new SAGetTIFSourceConfigRequest(sin);

        assertEquals(id, newReq.getId());
        assertEquals(version, newReq.getVersion());
    }

    public void testValidate() {
        String id = UUIDs.base64UUID();
        Long version = 1L;

        SAGetTIFSourceConfigRequest request = new SAGetTIFSourceConfigRequest(id, version);
        ActionRequestValidationException e = request.validate();
        assertNull(e);

        request = new SAGetTIFSourceConfigRequest("", 0L);
        e = request.validate();
        assertNotNull(e);
    }
}