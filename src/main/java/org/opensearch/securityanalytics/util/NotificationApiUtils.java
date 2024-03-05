/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.util;

import com.google.protobuf.BoolValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BackoffPolicy;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.notifications.NotificationsPluginInterface;
import org.opensearch.commons.notifications.action.*;
import org.opensearch.commons.notifications.model.ChannelMessage;
import org.opensearch.commons.notifications.model.EventSource;
import org.opensearch.commons.notifications.model.NotificationConfigInfo;
import org.opensearch.commons.notifications.model.SeverityType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.List;
import java.util.Set;

public class NotificationApiUtils {

    private static final Logger logger = LogManager.getLogger(NotificationApiUtils.class);
    /**
     * Extension function for publishing a notification to a channel in the Notification plugin.
     */
    public static void sendNotification(NodeClient client, String configId, String severity, List<String> channelIds) throws IOException {
        ChannelMessage message = NotificationApiHelper.generateMessage(configId);
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


}