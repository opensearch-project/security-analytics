package org.opensearch.securityanalytics.exceptions;

public class FeedStoreException extends RuntimeException {
    public FeedStoreException(final String message) {
        super(message);
    }

    public FeedStoreException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
