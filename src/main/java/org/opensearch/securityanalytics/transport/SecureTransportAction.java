
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.authuser.User;
import org.opensearch.rest.RestStatus;

class SecureTransportAction {

    private Booleab filterByEnabled: Boolean

    public void listenFilterBySettingChange(clusterService: ClusterService) {
        //clusterService.clusterSettings.addSettingsUpdateConsumer(AlertingSettings.FILTER_BY_BACKEND_ROLES) { filterByEnabled = it };
    }

    public void readUserFromThreadContext(client: Client): User? {
        String userStr = client
                .threadPool()
                .threadContext
                .getTransient<String>(ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT);
        log.debug("User and roles string from thread context: $userStr");
        return User.parse(userStr);
    }

    public void doFilterForUser(User user): Boolean {
        log.debug("Is filterByEnabled: $filterByEnabled ; Is admin user: ${isAdmin(user)}")
        if (isAdmin(user)) {
            return false;
        } else {
            return filterByEnabled;
        }
    }

    /**
     'all_access' role users are treated as admins.
     */
    private Boolean isAdmin(User user) {
        if(user == null) -> {
            return false
        }
        if(user.roles?.isNullOrEmpty() == true ){
            return false
        }
            else {
            return user.roles?.contains("all_access") == true
        }
    }

    //fun <T : Any> validateUserBackendRoles(user: User?, actionListener: ActionListener<T>): Boolean {
    public Boolean validateUserBackendRoles(User user, ActionListener<T> actionListener) {
        if (filterByEnabled) {
            if (user == null) {
                actionListener.onFailure(
                        //AlertingException.wrap(
                        OpenSearchStatusException(
                                "Filter by user backend roles is enabled with security disabled.", RestStatus.FORBIDDEN
                        )
                        //)
                );
                return false;
            } else if (isAdmin(user)) {
                return true;
            } else if (user.backendRoles.isNullOrEmpty()) {
                actionListener.onFailure(
                        //AlertingException.wrap(
                        OpenSearchStatusException("User doesn't have backend roles configured. Contact administrator", RestStatus.FORBIDDEN)
                        //)
                );
                return false;
            }
        }
        return true;
    }

    /**
     If FilterBy is enabled, this function verifies that the requester user has FilterBy permissions to access
     the resource. If FilterBy is disabled, will assume the user has permissions and return true.
     *
     This check will later to moved to the security plugin.
     */
    public Boolean checkUserPermissionsWithResource(
            User requesterUser,
            User resourceUser,
            ActionListener<T> actionListener,
            String resourceType,
            String resourceId
    ){

        if (!doFilterForUser(requesterUser)) return true;

        ArrayList resourceBackendRoles = resourceUser.backendRoles;
        ArrayList requesterBackendRoles = requesterUser.backendRoles;

        if (
                resourceBackendRoles == null ||
                        requesterBackendRoles == null ||
                        resourceBackendRoles.intersect(requesterBackendRoles).isEmpty()
        ) {
            actionListener.onFailure(
                    //AlertingException.wrap(
                    OpenSearchStatusException(
                            "Do not have permissions to resource, $resourceType, with id, $resourceId",
                            RestStatus.FORBIDDEN
                    )
                    //)
            );
            return false;
        }
        return true;
    }
}


