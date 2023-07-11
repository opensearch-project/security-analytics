/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.util.Collections;
import java.util.stream.Collectors;
import org.junit.Assert;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;

public class IndexDetectorRequestTests extends OpenSearchTestCase {

    public void testIndexDetectorPostRequest() throws IOException {
        String detectorId = UUID.randomUUID().toString();
        IndexDetectorRequest request = new IndexDetectorRequest(detectorId, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, randomDetector(List.of(UUID.randomUUID().toString())));

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorRequest newRequest = new IndexDetectorRequest(sin);
        Assert.assertEquals(detectorId, request.getDetectorId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getDetector());
    }

    public void testIndexDetectorPostRequest_2() throws IOException {
        String detectorId = UUID.randomUUID().toString();

        List<String> rules = List.of(UUID.randomUUID().toString());
        DetectorInput input1 = new DetectorInput("windows detector for security analytics", List.of("windows-1"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        DetectorInput input2 = new DetectorInput("windows detector for security analytics", List.of("windows-2"), Collections.emptyList(),
                rules.stream().map(DetectorRule::new).collect(Collectors.toList()));

        Detector detector = randomDetectorWithInputs(List.of(input1));
        IndexDetectorRequest request = new IndexDetectorRequest(detectorId, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, detector);

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