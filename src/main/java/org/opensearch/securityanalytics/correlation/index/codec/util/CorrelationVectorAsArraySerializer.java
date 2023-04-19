/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.util;

import org.opensearch.ExceptionsHelper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class CorrelationVectorAsArraySerializer implements CorrelationVectorSerializer {

    @Override
    public byte[] floatToByteArray(float[] input) {
        byte[] bytes;
        try(
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                ObjectOutputStream objectStream = new ObjectOutputStream(byteStream);
        ) {
            objectStream.writeObject(input);
            bytes = byteStream.toByteArray();
        } catch (IOException ex) {
            throw ExceptionsHelper.convertToOpenSearchException(ex);
        }
        return bytes;
    }

    @Override
    public float[] byteToFloatArray(ByteArrayInputStream byteStream) {
        try {
            ObjectInputStream objectStream  = new ObjectInputStream(byteStream);
            return (float[]) objectStream.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            throw ExceptionsHelper.convertToOpenSearchException(ex);
        }
    }
}