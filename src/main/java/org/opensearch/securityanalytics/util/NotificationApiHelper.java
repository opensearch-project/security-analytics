package org.opensearch.securityanalytics.util;

import org.opensearch.commons.notifications.model.ChannelMessage;
import org.opensearch.commons.notifications.model.EventSource;
import org.opensearch.commons.notifications.model.SeverityType;

import java.util.List;
/**
 * Helper class for sending test notifications.
 */
public class NotificationApiHelper {

    public static ChannelMessage generateMessage(String configId) {
        return new ChannelMessage(
                getMessageTextDescription(configId),
                getMessageHtmlDescription(configId),
                null
        );
    }

    public static EventSource generateEventSource(String configId, String severity, List<String> tags) {
        return new EventSource(
                getMessageTitle(configId),
                configId,
                SeverityType.INFO,
                tags
        );
    }

    private static String getMessageTitle(String configId) {
        return "Test Message Title-" + configId; // TODO: change as per spec
    }

    private static String getMessageTextDescription(String configId) {
        return "Test message content body for config id " + configId; // TODO: change as per spec
    }

    private static String getMessageHtmlDescription(String configId) {
        return "<html><header><title>Test Message</title></header><body><p>Test Message for config id " + configId + "</p></body></html>"; // TODO: change as per spec
    }
}
