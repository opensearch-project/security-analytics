/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.UUID;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;

public class IndexDetectorRequestTests extends OpenSearchTestCase {

    public void testIndexDetectorPostRequest() throws IOException {
        String detectorId = UUID.randomUUID().toString();
        IndexDetectorRequest request = new IndexDetectorRequest(detectorId, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, randomDetector());

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorRequest newRequest = new IndexDetectorRequest(sin);
        Assert.assertEquals(detectorId, request.getDetectorId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getDetector());
    }
}