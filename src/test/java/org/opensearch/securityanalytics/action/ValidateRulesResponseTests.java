/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.test.OpenSearchTestCase;


import static org.opensearch.securityanalytics.action.ValidateRulesRequest.RULES_FIELD;
import static org.opensearch.securityanalytics.action.ValidateRulesResponse.NONAPPLICABLE_FIELDS;

public class ValidateRulesResponseTests extends OpenSearchTestCase {

    public void testValidateRulesResponse_parseXContent() throws IOException {

        ValidateRulesResponse response = new ValidateRulesResponse(List.of("rule_id_1"));
        BytesReference bytes = BytesReference.bytes(response.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
        try (XContentParser xcp = createParser(JsonXContent.jsonXContent, bytes)) {
            if (xcp.currentToken() == null) {
                xcp.nextToken();
            }
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
            List<String> ruleIds = null;
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();
                assertEquals(NONAPPLICABLE_FIELDS, fieldName);
                ruleIds = new ArrayList<>();
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                    ruleIds.add(xcp.text());
                }
            }
            assertEquals(1, ruleIds.size());
            assertEquals("rule_id_1", ruleIds.get(0));
        }
    }

    public void testValidateRulesResponse_streams() throws IOException {
        ValidateRulesResponse response = new ValidateRulesResponse(List.of("rule_id_1", "rule_id_2"));
        Assert.assertNotNull(response);

        BytesStreamOutput out = new BytesStreamOutput();
        response.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        ValidateRulesResponse newResponse = new ValidateRulesResponse(sin);
        assertEquals(2, newResponse.getNonapplicableFields().size());
        assertEquals("rule_id_1", newResponse.getNonapplicableFields().get(0));
        assertEquals("rule_id_2", newResponse.getNonapplicableFields().get(1));
    }

}
