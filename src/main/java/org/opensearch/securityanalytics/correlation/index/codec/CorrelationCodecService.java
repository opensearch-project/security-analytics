/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec;

import org.apache.lucene.codecs.Codec;
import org.opensearch.index.codec.CodecService;
import org.opensearch.index.codec.CodecServiceConfig;
import org.opensearch.index.mapper.MapperService;

public class CorrelationCodecService extends CodecService {

    private final MapperService mapperService;

    public CorrelationCodecService(CodecServiceConfig codecServiceConfig) {
        super(codecServiceConfig.getMapperService(), codecServiceConfig.getLogger());
        mapperService = codecServiceConfig.getMapperService();
    }

    @Override
    public Codec codec(String name) {
        return CorrelationCodecVersion.current().getCorrelationCodecSupplier().apply(super.codec(name), mapperService);
    }
}