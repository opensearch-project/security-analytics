/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.randomUser;

public class IndexDetectorResponseTests extends OpenSearchTestCase {

    public void testIndexDetectorPostResponse() throws IOException {
        String cronExpression = "31 * * * *";
        Instant testInstance = Instant.ofEpochSecond(1538164858L);

        CronSchedule cronSchedule = new CronSchedule(cronExpression, ZoneId.of("Asia/Kolkata"), testInstance);

        Detector detector = new Detector(
                "123",
                0L,
                "test-monitor",
                true,
                cronSchedule,
                Instant.now(),
                Instant.now(),
                Detector.DetectorType.LINUX,
                randomUser(),
                List.of(),
                "456",
                ".windows-detectors-index"
        );
        IndexDetectorResponse response = new IndexDetectorResponse("1234", 1L, RestStatus.OK, detector);
        Assert.assertNotNull(response);

        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexDetectorResponse newResponse = new IndexDetectorResponse(sin);

        Assert.assertEquals("1234", newResponse.getId());
        Assert.assertEquals(1L, newResponse.getVersion().longValue());
        Assert.assertEquals(RestStatus.OK, newResponse.getStatus());
        Assert.assertNotNull(newResponse.getDetector());
    }
}