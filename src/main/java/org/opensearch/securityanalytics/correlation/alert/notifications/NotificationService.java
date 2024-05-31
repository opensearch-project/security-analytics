package org.opensearch.securityanalytics.correlation.alert.notifications;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.notifications.NotificationsPluginInterface;
import org.opensearch.commons.notifications.action.*;
import org.opensearch.commons.notifications.model.ChannelMessage;
import org.opensearch.commons.notifications.model.EventSource;
import org.opensearch.commons.notifications.model.SeverityType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import org.opensearch.script.Script;
import org.opensearch.script.ScriptService;
import org.opensearch.script.TemplateScript;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NotificationService {

    private static final Logger logger = LogManager.getLogger(NotificationService.class);

    private static ScriptService scriptService;
    /**
     * Extension function for publishing a notification to a channel in the Notification plugin.
     */
    public static void sendNotification(NodeClient client, String configId, String severity, List<String> channelIds) throws IOException {
        ChannelMessage message = generateMessage(configId);
        NotificationsPluginInterface.INSTANCE.sendNotification(client, new EventSource(configId, configId, SeverityType.CRITICAL, channelIds), message, channelIds, new ActionListener<SendNotificationResponse>() {
            @Override
            public void onResponse(SendNotificationResponse sendNotificationResponse) {
                if(sendNotificationResponse.getStatus() == RestStatus.OK) {
                    logger.info("Successfully sent a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent());
                }
                else {
                    logger.error("Successfully sent a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent());
                }

            }
            @Override
            public void onFailure(Exception e) {
                logger.error("Failed while sending a notification: " + e.toString());
                new SecurityAnalyticsException("Failed to send notification", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }
    public static String compileTemplate(Script template, CorrelationAlertContext ctx) {
        TemplateScript.Factory factory = scriptService.compile(template, TemplateScript.CONTEXT);
        Map<String, Object> params = new HashMap<>(template.getParams());
        params.put("ctx", ctx.asTemplateArg());
        TemplateScript templateScript = factory.newInstance(params);
        return templateScript.execute();
    }

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
