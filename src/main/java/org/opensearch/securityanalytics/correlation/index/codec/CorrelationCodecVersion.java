/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec;

import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.lucene95.Lucene95Codec;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.index.codec.correlation950.CorrelationCodec;
import org.opensearch.securityanalytics.correlation.index.codec.correlation950.PerFieldCorrelationVectorsFormat;

import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public enum CorrelationCodecVersion {
    V_9_5_0(
            "CorrelationCodec",
            new Lucene95Codec(),
            new PerFieldCorrelationVectorsFormat(Optional.empty()),
            (userCodec, mapperService) -> new CorrelationCodec(userCodec, new PerFieldCorrelationVectorsFormat(Optional.of(mapperService))),
            CorrelationCodec::new
    );

    private static final CorrelationCodecVersion CURRENT = V_9_5_0;
    private final String codecName;
    private final Codec defaultCodecDelegate;
    private final PerFieldCorrelationVectorsFormat perFieldCorrelationVectorsFormat;
    private final BiFunction<Codec, MapperService, Codec> correlationCodecSupplier;
    private final Supplier<Codec> defaultCorrelationCodecSupplier;

    CorrelationCodecVersion(String codecName,
                            Codec defaultCodecDelegate,
                            PerFieldCorrelationVectorsFormat perFieldCorrelationVectorsFormat,
                            BiFunction<Codec, MapperService, Codec> correlationCodecSupplier,
                            Supplier<Codec> defaultCorrelationCodecSupplier) {
        this.codecName = codecName;
        this.defaultCodecDelegate = defaultCodecDelegate;
        this.perFieldCorrelationVectorsFormat = perFieldCorrelationVectorsFormat;
        this.correlationCodecSupplier = correlationCodecSupplier;
        this.defaultCorrelationCodecSupplier = defaultCorrelationCodecSupplier;
    }

    public String getCodecName() {
        return codecName;
    }

    public Codec getDefaultCodecDelegate() {
        return defaultCodecDelegate;
    }

    public PerFieldCorrelationVectorsFormat getPerFieldCorrelationVectorsFormat() {
        return perFieldCorrelationVectorsFormat;
    }

    public BiFunction<Codec, MapperService, Codec> getCorrelationCodecSupplier() {
        return correlationCodecSupplier;
    }

    public Supplier<Codec> getDefaultCorrelationCodecSupplier() {
        return defaultCorrelationCodecSupplier;
    }

    public static final CorrelationCodecVersion current() {
        return CURRENT;
    }
}