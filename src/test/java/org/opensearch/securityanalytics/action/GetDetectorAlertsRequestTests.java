package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class GetDetectorAlertsRequestTests extends OpenSearchTestCase {

    public void testGetDetectorAlertsRequest() throws IOException {

        String detectorId = "detectorId";
        GetDetectorAlertsRequest request = new GetDetectorAlertsRequest(detectorId, "active", "1",
                new Table("asc", "sortString", null, 1, 0, ""));

        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        GetDetectorAlertsRequest getDetectorAlertsRequest = new GetDetectorAlertsRequest(sin);
        Assert.assertEquals(detectorId, getDetectorAlertsRequest.getDetectorId());
    }
}
