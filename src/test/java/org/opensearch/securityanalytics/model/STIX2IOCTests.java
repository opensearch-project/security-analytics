/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
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
}
