/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.junit.Assert;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;


import static org.opensearch.securityanalytics.TestHelpers.randomDetector;

public class ValidateRulesRequestTests extends OpenSearchTestCase {

    public void testValidateRulesRequest_parseXContent() throws IOException {

        String source = "{" +
                "\"index_name\": \"my_index_111\"," +
                "\"rules\": [ \"rule_id_1\", \"rule_id_2\" ]" +
                "}";
        ValidateRulesRequest req;
        try (XContentParser xcp = createParser(JsonXContent.jsonXContent, source)) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
            req = ValidateRulesRequest.parse(xcp);
        }
        assertEquals("my_index_111", req.getIndexName());
        assertEquals(2, req.getRules().size());
        assertEquals("rule_id_1", req.getRules().get(0));
        assertEquals("rule_id_2", req.getRules().get(1));
    }

    public void testValidateRulesRequest_streams() throws IOException {
        String indeName = "my_index_1";
        ValidateRulesRequest request = new ValidateRulesRequest(indeName, List.of("rule_id_1", "rule_id_2"));
        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        ValidateRulesRequest newRequest = new ValidateRulesRequest(sin);
        assertEquals(indeName, newRequest.getIndexName());
        assertEquals(2, newRequest.getRules().size());
        assertEquals("rule_id_1", newRequest.getRules().get(0));
        assertEquals("rule_id_2", newRequest.getRules().get(1));
    }

}
