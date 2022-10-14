/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.authuser.User;
import org.opensearch.threadpool.ThreadPool;

import java.util.List;
import java.util.stream.Collectors;

public interface SecureTransportAction {

    static final Logger log = LogManager.getLogger(SecureTransportAction.class);

    default User readUserFromThreadContext(ThreadPool threadPool) {
        String userStr = threadPool.getThreadContext().getTransient(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT);
        log.debug("User and roles string from thread context: {}", userStr);
        return User.parse(userStr);
    }

    default boolean doFilterForUser(User user, boolean filterByEnabled ) {
        log.debug("Is filterByEnabled: {} ; Is admin user: {}", filterByEnabled, isAdmin(user));
        if (isAdmin(user)) {
            return false;
        } else {
            return filterByEnabled;
        }
    }

    /**
     *  'all_access' role users are treated as admins.
     */
    default boolean isAdmin(User user) {
        if (user == null) {
            return false;
        }
        if  (user.getRoles().size() == 0) {
            return false;
        }
        return user.getRoles().contains("all_access");
    }

    default String validateUserBackendRoles(User user, boolean filterByEnabled) {
        if (filterByEnabled) {
            if (user == null) {
                return "Filter by user backend roles is enabled with security disabled.";
            } else if (isAdmin(user)) {
                return "";
            } else if (user.getBackendRoles().size() == 0) {
                return "User doesn't have backend roles configured. Contact administrator";
            }
        }
        return "";
    }

    /**
     * If FilterBy is enabled, this function verifies that the requester user has FilterBy permissions to access
     * the resource. If FilterBy is disabled, we will assume the user has permissions and return true.
     *
     * This check will later to moved to the security plugin.
     */
    default boolean  checkUserPermissionsWithResource(
            User requesterUser,
            User resourceUser,
            String resourceType,
            String resourceId,
            boolean filterByEnabled
    ) {

        if (!doFilterForUser(requesterUser, filterByEnabled)) return true;

        List<String> resourceBackendRoles = resourceUser.getBackendRoles();
        List<String> requesterBackendRoles = requesterUser.getBackendRoles();

        if (
                resourceBackendRoles == null ||requesterBackendRoles == null ||
                        isIntersectListsEmpty(resourceBackendRoles, requesterBackendRoles)
        ) {
            return false;
        }
        return true;
    }


    default boolean isIntersectListsEmpty(List<String> a, List<String> b) {
        return (a.stream()
                .distinct()
                .filter(b::contains)
                .collect(Collectors.toSet()).size()==0);
    }
}