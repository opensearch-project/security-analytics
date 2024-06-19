/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.randomSATIFSourceConfigDto;

public class IndexTIFSourceConfigRequestTests extends OpenSearchTestCase {

    public void testTIFSourceConfigPostRequest() throws IOException {
        SATIFSourceConfigDto saTifSourceConfigDto = randomSATIFSourceConfigDto();
        String id = saTifSourceConfigDto.getId();
        SAIndexTIFSourceConfigRequest request = new SAIndexTIFSourceConfigRequest(id, RestRequest.Method.POST, saTifSourceConfigDto);
        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SAIndexTIFSourceConfigRequest newRequest = new SAIndexTIFSourceConfigRequest(sin);
        Assert.assertEquals(id, request.getTIFConfigId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getTIFConfigDto());
    }
}