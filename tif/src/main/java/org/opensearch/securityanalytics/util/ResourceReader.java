package org.opensearch.securityanalytics.util;

import org.opensearch.securityanalytics.exceptions.ResourceReaderException;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class ResourceReader {
    public String readResourceAsString(final String resourcePath) {
        final Optional<Path> optionalResourcePath = Optional.of(getClass())
                .map(Class::getClassLoader)
                .map(classLoader -> classLoader.getResource(resourcePath))
                .map(URL::getPath)
                .map(Path::of);

        if (optionalResourcePath.isEmpty()) {
            throw new ResourceReaderException(String.format("Unable to find resource [%s]", resourcePath));
        }

        try {
            return Files.readString(optionalResourcePath.get());
        } catch (final Exception e) {
            throw new ResourceReaderException(String.format("Unable to read resource [%s]", resourcePath));
        }
    }
}
