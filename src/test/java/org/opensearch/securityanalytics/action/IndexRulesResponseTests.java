/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

public class IndexRulesResponseTests extends OpenSearchTestCase {

    public void testIndexRulesPostResponse() throws IOException {
        IndexRulesResponse response = new IndexRulesResponse(0L, RestStatus.OK);

        Assert.assertNotNull(response);

        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        IndexRulesResponse newResponse = new IndexRulesResponse(sin);
        Assert.assertEquals(RestStatus.OK, newResponse.getStatus());
        Assert.assertEquals(0L, newResponse.getRuleCount().longValue());
    }
}