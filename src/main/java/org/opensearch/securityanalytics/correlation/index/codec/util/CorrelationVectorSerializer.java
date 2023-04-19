/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.util;

import java.io.ByteArrayInputStream;

public interface CorrelationVectorSerializer {

    byte[] floatToByteArray(float[] input);

    float[] byteToFloatArray(ByteArrayInputStream byteStream);
}