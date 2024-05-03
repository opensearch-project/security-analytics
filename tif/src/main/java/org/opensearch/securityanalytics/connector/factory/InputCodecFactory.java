/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.factory;

import org.opensearch.securityanalytics.connector.codec.InputCodec;
import org.opensearch.securityanalytics.factory.BinaryParameterCachingFactory;
import org.opensearch.securityanalytics.model.IOCSchema;
import org.opensearch.securityanalytics.connector.model.InputCodecSchema;

public class InputCodecFactory extends BinaryParameterCachingFactory<InputCodecSchema, IOCSchema, InputCodec> {
    @Override
    protected InputCodec doCreate(final InputCodecSchema inputCodecSchema, final IOCSchema iocSchema) {
        return inputCodecSchema.getInputCodecConstructor().apply(iocSchema);
    }
}
