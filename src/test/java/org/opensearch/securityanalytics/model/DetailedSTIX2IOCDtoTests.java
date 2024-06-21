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

public class DetailedSTIX2IOCDtoTests extends OpenSearchTestCase {
    public void testAsStream() throws IOException {
        long numFindings = randomLongBetween(0, 100);
        DetailedSTIX2IOCDto ioc = new DetailedSTIX2IOCDto(randomIocDto(), numFindings);
        BytesStreamOutput out = new BytesStreamOutput();
        ioc.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        DetailedSTIX2IOCDto newIoc = new DetailedSTIX2IOCDto(sin);
        assertEqualIocDtos(ioc, newIoc);
    }

    public void testParseFunction() throws IOException {
        long numFindings = randomLongBetween(0, 100);
        DetailedSTIX2IOCDto ioc = new DetailedSTIX2IOCDto(randomIocDto(), numFindings);
        String json = toJsonString(ioc);
        DetailedSTIX2IOCDto newIoc = DetailedSTIX2IOCDto.parse(parser(json), ioc.getIoc().getId(), ioc.getIoc().getVersion());
        assertEqualIocDtos(ioc, newIoc);
    }
}
