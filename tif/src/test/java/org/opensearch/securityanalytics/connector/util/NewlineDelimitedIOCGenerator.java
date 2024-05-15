package org.opensearch.securityanalytics.connector.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.STIX2;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.List;

public class NewlineDelimitedIOCGenerator implements IOCGenerator {
    private final ObjectMapper objectMapper;
    private final STIX2Generator stix2Generator;

    public NewlineDelimitedIOCGenerator() {
        this.objectMapper = new ObjectMapper();
        this.stix2Generator = new STIX2Generator();
    }

    @Override
    public void write(final int numberOfIOCs, final OutputStream outputStream) {
        try (final PrintWriter printWriter = new PrintWriter(outputStream)) {
            writeLines(numberOfIOCs, printWriter);
        }
    }

    private void writeLines(final int numberOfIOCs, final PrintWriter printWriter) {
        final List<IOC> iocs = stix2Generator.generateSTIX2(numberOfIOCs);
        iocs.forEach(ioc -> writeLine(ioc, printWriter));
    }

    private void writeLine(final IOC ioc, final PrintWriter printWriter) {
        try {
            final String iocAsString = objectMapper.writeValueAsString(ioc);
            printWriter.write(iocAsString + "\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
