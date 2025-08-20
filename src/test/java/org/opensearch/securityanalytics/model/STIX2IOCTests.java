/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.parser;
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.assertEqualIOCs;
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.randomIOC;
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.toJsonString;

public class STIX2IOCTests extends OpenSearchTestCase {
    public void testAsStream() throws IOException {
        STIX2IOC ioc = randomIOC();
        BytesStreamOutput out = new BytesStreamOutput();
        ioc.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        STIX2IOC newIoc = new STIX2IOC(sin);
        assertEqualIOCs(ioc, newIoc);
    }

    public void testParseFunction() throws IOException {
        STIX2IOC ioc = randomIOC();
        String json = toJsonString(ioc);
        STIX2IOC newIoc = STIX2IOC.parse(parser(json), ioc.getId(), ioc.getVersion());
        assertEqualIOCs(ioc, newIoc);
    }

    public void testParseFunction_customType() throws IOException {
        // Execute test case for each IOCType
        for (String type : IOCType.types) {
            STIX2IOC ioc = randomIOC(type);
            String json = toJsonString(ioc);

            // Replace the IOCType with a fake type
            String fakeType = "fake" + type;
            final String invalidJson = json.replace(type, fakeType);

            STIX2IOC parsedIoc = STIX2IOC.parse(parser(invalidJson), ioc.getId(), ioc.getVersion());
            assertEquals(parsedIoc.getType(), fakeType);
        }
    }
}
