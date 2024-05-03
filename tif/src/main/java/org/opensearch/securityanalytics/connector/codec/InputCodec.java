/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.codec;

import org.opensearch.securityanalytics.model.IOC;

import java.io.InputStream;
import java.util.List;

public interface InputCodec {
    /**
     * Parses an {@link InputStream} into the provided type.
     *
     * @param inputStream The input stream for code to process
     * @return List<IOC> A list of IOCs parsed from the input stream
     */
    List<IOC> parse(InputStream inputStream);
}
