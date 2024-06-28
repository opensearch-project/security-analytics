/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.utils.testUtils.PojoGenerator;
import org.opensearch.securityanalytics.model.DetailedSTIX2IOCDto;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.opensearch.securityanalytics.TestHelpers.randomLowerCaseString;
import static org.opensearch.test.OpenSearchTestCase.randomInt;
import static org.opensearch.test.OpenSearchTestCase.randomLong;

public class STIX2IOCGenerator implements PojoGenerator {
    List<STIX2IOC> iocs;

    // Optional value. When not null, all IOCs generated will use this type.
    IOCType type;

    private final ObjectMapper objectMapper;

    public STIX2IOCGenerator() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void write(final int numberOfIOCs, final OutputStream outputStream) {
        try (final PrintWriter printWriter = new PrintWriter(outputStream)) {
            writeLines(numberOfIOCs, printWriter);
        }
    }

    private void writeLines(final int numberOfIOCs, final PrintWriter printWriter) {
        final List<STIX2IOC> iocs = IntStream.range(0, numberOfIOCs)
                .mapToObj(i -> randomIOC(type))
                .collect(Collectors.toList());
        this.iocs = iocs;
        iocs.forEach(ioc -> writeLine(ioc, printWriter));
    }

    private void writeLine(final IOC ioc, final PrintWriter printWriter) {
        try {
            final String iocAsString;
            if (ioc.getClass() == STIX2IOC.class) {
                iocAsString = BytesReference.bytes(((STIX2IOC) ioc).toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)).utf8ToString();
            } else {
                iocAsString = objectMapper.writeValueAsString(ioc);
            }
            printWriter.write(iocAsString + "\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static STIX2IOC randomIOC(IOCType type) {
        return randomIOC(
                null,
                null,
                type,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    public static STIX2IOC randomIOC() {
        return randomIOC(null);
    }

    public List<STIX2IOC> getIocs() {
        return iocs;
    }

    public IOCType getType() {
        return type;
    }

    public void setType(IOCType type) {
        this.type = type;
    }

    public static STIX2IOC randomIOC(
            String id,
            String name,
            IOCType type,
            String value,
            String severity,
            Instant created,
            Instant modified,
            String description,
            List<String> labels,
            String specVersion,
            String feedId,
            String feedName,
            Long version
    ) {
        if (name == null) {
            name = randomLowerCaseString();
        }
        if (type == null) {
            type = IOCType.values()[randomInt(IOCType.values().length - 1)];
        }
        if (value == null) {
            value = randomLowerCaseString();
        }
        if (severity == null) {
            severity = randomLowerCaseString();
        }
        if (created == null) {
            created = Instant.now();
        }
        if (modified == null) {
            modified = Instant.now().plusSeconds(3600); // 1 hour
        }
        if (description == null) {
            description = randomLowerCaseString();
        }
        if (labels == null) {
            labels = IntStream.range(0, randomInt(5))
                    .mapToObj(i -> randomLowerCaseString())
                    .collect(Collectors.toList());
        }
        if (specVersion == null) {
            specVersion = randomLowerCaseString();
        }
        if (feedId == null) {
            feedId = randomLowerCaseString();
        }
        if (feedName == null) {
            feedName = randomLowerCaseString();
        }
        if (version == null) {
            version = randomLong();
        }

        return new STIX2IOC(
                id,
                name,
                type,
                value,
                severity,
                created,
                modified,
                description,
                labels,
                specVersion,
                feedId,
                feedName,
                version
        );
    }

    public static STIX2IOCDto randomIocDto() {
        return new STIX2IOCDto(randomIOC());
    }

    public static STIX2IOCDto randomIocDto(
            String id,
            String name,
            IOCType type,
            String value,
            String severity,
            Instant created,
            Instant modified,
            String description,
            List<String> labels,
            String specVersion,
            String feedId,
            String feedName,
            Long version
    ) {
        return new STIX2IOCDto(randomIOC(
                id,
                name,
                type,
                value,
                severity,
                created,
                modified,
                description,
                labels,
                specVersion,
                feedId,
                feedName,
                version
        ));
    }

    public static String toJsonString(STIX2IOC ioc) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = ioc.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static String toJsonString(STIX2IOCDto ioc) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = ioc.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static String toJsonString(DetailedSTIX2IOCDto ioc) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = ioc.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static void assertIOCEqualsDTO(STIX2IOC ioc, STIX2IOCDto iocDto) {
        STIX2IOC newIoc = new STIX2IOC(iocDto);
        assertEqualIOCs(ioc, newIoc);
    }

    public static void assertEqualIOCs(STIX2IOC ioc, STIX2IOC newIoc) {
        assertNotNull(newIoc.getId());
        assertEquals(ioc.getName(), newIoc.getName());
        assertEquals(ioc.getValue(), newIoc.getValue());
        assertEquals(ioc.getSeverity(), newIoc.getSeverity());
//        assertEquals(ioc.getCreated(), newIoc.getCreated());
//        assertEquals(ioc.getModified(), newIoc.getModified());
        assertEquals(ioc.getDescription(), newIoc.getDescription());
        assertEquals(ioc.getLabels(), newIoc.getLabels());
        assertEquals(ioc.getSpecVersion(), newIoc.getSpecVersion());
        assertEquals(ioc.getFeedId(), newIoc.getFeedId());
        assertEquals(ioc.getFeedName(), newIoc.getFeedName());
    }

    public static void assertEqualIocDtos(STIX2IOCDto ioc, STIX2IOCDto newIoc) {
        assertNotNull(newIoc.getId());
        assertEquals(ioc.getName(), newIoc.getName());
        assertEquals(ioc.getValue(), newIoc.getValue());
        assertEquals(ioc.getSeverity(), newIoc.getSeverity());
//        assertEquals(ioc.getCreated(), newIoc.getCreated());
//        assertEquals(ioc.getModified(), newIoc.getModified());
        assertEquals(ioc.getDescription(), newIoc.getDescription());
        assertEquals(ioc.getLabels(), newIoc.getLabels());
        assertEquals(ioc.getSpecVersion(), newIoc.getSpecVersion());
        assertEquals(ioc.getFeedId(), newIoc.getFeedId());
        assertEquals(ioc.getFeedName(), newIoc.getFeedName());
    }

    public static void assertEqualIocDtos(DetailedSTIX2IOCDto ioc, DetailedSTIX2IOCDto newIoc) {
        assertEqualIocDtos(ioc.getIoc(), newIoc.getIoc());
        assertEquals(ioc.getNumFindings(), newIoc.getNumFindings());
    }

    public static String getListIOCsURI() {
        return String.format("%s", SecurityAnalyticsPlugin.LIST_IOCS_URI);

    }
}
