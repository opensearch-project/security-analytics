package org.opensearch.securityanalytics.connector.util;

import java.io.IOException;
import java.io.OutputStream;

public interface IOCGenerator {
    void write(int numberOfIOCs, OutputStream outputStream) throws IOException;
}
