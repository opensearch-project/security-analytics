/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

public class AckAlertsRequestTests extends OpenSearchTestCase {

    public void testStreamInOut() throws IOException {
        BytesStreamOutput out = new BytesStreamOutput();

        AckAlertsRequest req = new AckAlertsRequest("d1", Arrays.asList("a1", "a2", "a3"));
        req.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        AckAlertsRequest newReq = new AckAlertsRequest(sin);

        assertTrue(newReq.getAlertIds().contains("a1"));
        assertTrue(newReq.getAlertIds().contains("a2"));
        assertTrue(newReq.getAlertIds().contains("a3"));
        assertTrue(newReq.getDetectorId().contains("d1"));
    }

    public void testValidate() {
        AckAlertsRequest req = new AckAlertsRequest(null, Arrays.asList("a1", "a2", "a3"));
        ActionRequestValidationException validate = req.validate();
        assertTrue(validate != null);
        assertTrue(validate.getMessage().contains("detector id is mandatory"));
        AckAlertsRequest req1 = new AckAlertsRequest("d1", Collections.emptyList());
        validate = req1.validate();
        assertTrue(validate.getMessage().contains("alert ids list cannot be empty"));

    }
}
