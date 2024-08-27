/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert.notifications;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.notifications.NotificationsPluginInterface;
import org.opensearch.commons.notifications.action.*;
import org.opensearch.commons.notifications.model.ChannelMessage;
import org.opensearch.commons.notifications.model.EventSource;
import org.opensearch.commons.notifications.model.SeverityType;
import org.opensearch.commons.notifications.action.GetNotificationConfigRequest;
import org.opensearch.commons.notifications.action.GetNotificationConfigResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.threatIntel.iocscan.service.ThreatIntelAlertContext;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.script.ScriptService;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Collections;

import org.opensearch.script.Script;
import org.opensearch.script.TemplateScript;

public class NotificationService {

    private static final Logger logger = LogManager.getLogger(NotificationService.class);

    private static ScriptService scriptService;
    private final NodeClient client;

    public NotificationService(NodeClient client, ScriptService scriptService) {
        this.client = client;
        this.scriptService = scriptService;
    }

    /**
     * Extension function for publishing a notification to a channel in the Notification plugin.
     */
    public void sendNotification(String configId, String severity, String subject, String notificationMessageText) throws IOException {
        ChannelMessage message = generateMessage(notificationMessageText);
        List<String> channelIds = new ArrayList<>();
        channelIds.add(configId);
        SeverityType severityType = SeverityType.Companion.fromTagOrDefault(severity);
        NotificationsPluginInterface.INSTANCE.sendNotification(client, new EventSource(subject, configId, severityType, Collections.emptyList()), message, channelIds, new ActionListener<SendNotificationResponse>() {
            @Override
            public void onResponse(SendNotificationResponse sendNotificationResponse) {
                if (sendNotificationResponse.getStatus() == RestStatus.OK) {
                    logger.info("Successfully sent a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent());
                } else {
                    logger.error("Error while sending a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent());
                }
            }
            @Override
            public void onFailure(Exception e) {
                logger.error("Failed while sending a notification with " + configId, e);
            }
        });
    }

    /**
     * Extension function for publishing a notification to a channel in the Notification plugin.
     */
    public void sendNotification(String configId, String severity, String subject, String notificationMessageText,
                                 ActionListener<Void> listener) {
        ChannelMessage message = generateMessage(notificationMessageText);
        List<String> channelIds = new ArrayList<>();
        channelIds.add(configId);
        SeverityType severityType = SeverityType.Companion.fromTagOrDefault(severity);
        NotificationsPluginInterface.INSTANCE.sendNotification(client, new EventSource(subject, configId, severityType, Collections.emptyList()), message, channelIds, ActionListener.wrap(
                sendNotificationResponse -> {
                    if (sendNotificationResponse.getStatus() == RestStatus.OK) {
                        logger.info("Successfully sent a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent());
                    } else {
                        listener.onFailure(new Exception("Error while sending a notification, Notification Event: " + sendNotificationResponse.getNotificationEvent()));
                    }

                }, e -> {
                    logger.error("Failed while sending a notification with " + configId, e);
                    listener.onFailure(e);
                }
        ));
    }

    /**
     * Gets a NotificationConfigInfo object by ID if it exists.
     */
    public GetNotificationConfigResponse getNotificationConfigInfo(String id) {

        Set idSet = new HashSet<String>();
        idSet.add(id);
        GetNotificationConfigRequest getNotificationConfigRequest = new GetNotificationConfigRequest(idSet, 0, 10, null, null, new HashMap<>());
        GetNotificationConfigResponse configResp = null;
        NotificationsPluginInterface.INSTANCE.getNotificationConfig(client, getNotificationConfigRequest, new ActionListener<GetNotificationConfigResponse>() {
            @Override
            public void onResponse(GetNotificationConfigResponse getNotificationConfigResponse) {
                if (getNotificationConfigResponse.getStatus() == RestStatus.OK) {
                    getNotificationConfigResponse = configResp;
                } else {
                    logger.error("Successfully sent a notification, Notification Event: " + getNotificationConfigResponse);
                }
            }

            @Override
            public void onFailure(Exception e) {
                logger.error("Notification config [" + id + "] was not found");
                new SecurityAnalyticsException("Failed to fetch notification config", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
        logger.info("Notification config response is: {} ", configResp);
        return configResp;
    }

    public static ChannelMessage generateMessage(String message) {
        return new ChannelMessage(
                message,
                null,
                null
        );
    }

    public static String compileTemplate(CorrelationAlertContext ctx, Script template) {
        return compileTemplateGeneric(template, ctx.asTemplateArg());
    }

    public static String compileTemplate(ThreatIntelAlertContext ctx, Script template) {
        return compileTemplateGeneric(template, ctx.asTemplateArg());
    }

    private static String compileTemplateGeneric(Script template, Map<String, Object> templateArg) {
        TemplateScript.Factory factory = scriptService.compile(template, TemplateScript.CONTEXT);
        Map<String, Object> params = new HashMap<>(template.getParams());
        params.put("ctx", templateArg);
        TemplateScript templateScript = factory.newInstance(params);
        return templateScript.execute();
    }

}
