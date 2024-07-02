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
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.assertEqualIocDtos;
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.randomIocDto;
import static org.opensearch.securityanalytics.util.STIX2IOCGenerator.toJsonString;

public class STIX2IOCDtoTests extends OpenSearchTestCase {
    public void testAsStream() throws IOException {
        STIX2IOCDto ioc = randomIocDto();
        BytesStreamOutput out = new BytesStreamOutput();
        ioc.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        STIX2IOCDto newIoc = new STIX2IOCDto(sin);
        assertEqualIocDtos(ioc, newIoc);
    }

    public void testParseFunction() throws IOException {
        STIX2IOCDto ioc = randomIocDto();
        String json = toJsonString(ioc);
        STIX2IOCDto newIoc = STIX2IOCDto.parse(parser(json), ioc.getId(), ioc.getVersion());
        assertEqualIocDtos(ioc, newIoc);
    }
}
