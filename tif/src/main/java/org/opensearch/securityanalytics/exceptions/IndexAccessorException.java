package org.opensearch.securityanalytics.exceptions;

public class IndexAccessorException extends RuntimeException {
    public IndexAccessorException(final String message) {
        super(message);
    }

    public IndexAccessorException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
