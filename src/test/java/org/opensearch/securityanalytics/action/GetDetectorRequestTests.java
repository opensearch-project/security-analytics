/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class GetDetectorRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        GetDetectorRequest getDetectorRequest = new GetDetectorRequest("detectorId-123", 0L);
        getDetectorRequest.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        GetDetectorRequest newReq = new GetDetectorRequest(sin);

        assertEquals("detectorId-123", newReq.getDetectorId());
    }

    public void testValidate() {
        GetDetectorRequest getDetectorRequest = new GetDetectorRequest("detectorId-123", 0L);
        ActionRequestValidationException e = getDetectorRequest.validate();
        assertNull(e);

        getDetectorRequest = new GetDetectorRequest("", 0L);
        e = getDetectorRequest.validate();
        assertNotNull(e);
    }
}
