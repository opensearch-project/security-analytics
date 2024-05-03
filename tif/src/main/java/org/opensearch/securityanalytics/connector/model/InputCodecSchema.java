package org.opensearch.securityanalytics.connector.model;

import org.opensearch.securityanalytics.connector.codec.InputCodec;
import org.opensearch.securityanalytics.connector.codec.NewlineDelimitedJsonCodec;
import org.opensearch.securityanalytics.model.IOCSchema;

import java.util.function.Function;

public enum InputCodecSchema {
    ND_JSON(iocSchema -> new NewlineDelimitedJsonCodec(iocSchema.getModelClass()));

    private final Function<IOCSchema, InputCodec> inputCodecConstructor;

    InputCodecSchema(final Function<IOCSchema, InputCodec> inputCodecConstructor) {
        this.inputCodecConstructor = inputCodecConstructor;
    }

    public Function<IOCSchema, InputCodec> getInputCodecConstructor() {
        return inputCodecConstructor;
    }
}
