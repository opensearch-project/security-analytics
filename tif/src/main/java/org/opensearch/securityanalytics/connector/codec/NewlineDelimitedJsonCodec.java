package org.opensearch.securityanalytics.connector.codec;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import com.google.common.annotations.VisibleForTesting;
import org.opensearch.securityanalytics.exceptions.ConnectorParsingException;
import org.opensearch.securityanalytics.model.IOC;

import java.io.InputStream;
import java.util.List;

public class NewlineDelimitedJsonCodec implements InputCodec {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().registerModule(new AfterburnerModule());
    private final ObjectReader objectReader;

    public NewlineDelimitedJsonCodec(final Class<? extends IOC> clazz) {
        this.objectReader = OBJECT_MAPPER.readerFor(clazz);
    }

    @VisibleForTesting
    NewlineDelimitedJsonCodec(final ObjectReader objectReader) {
        this.objectReader = objectReader;
    }

    @Override
    public List<IOC> parse(final InputStream inputStream) {
        try {
            final MappingIterator<IOC> mappingIterator = objectReader.readValues(inputStream);
            return mappingIterator.readAll();
        } catch (final Exception e) {
            throw new ConnectorParsingException(e);
        }
    }
}
