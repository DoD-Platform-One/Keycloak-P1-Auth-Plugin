package dod.p1.keycloak.utils;

import org.keycloak.models.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * A minimal, no-op implementation of Keycloak's UserModel,
 * primarily intended for testing or stubbing scenarios.
 *
 * <p>All methods are either no-ops or return null or fixed values.
 * Adjust fields, methods, or return values as needed to simulate
 * certain test conditions or behaviors.</p>
 */
public class UserModelDefaultMethodsImpl extends UserModelDefaultMethods {

    // Example fixed email return value, for demonstration
    private static final String DEFAULT_EMAIL = "test.user@test.mil";

    @Override
    public String getId() {
        // Return a fixed or null ID as needed
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public void setUsername(String username) {
        // No-op
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public void setEnabled(boolean enabled) {
        // No-op
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        // No-op
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        // No-op
    }

    @Override
    public void removeAttribute(String name) {
        // No-op
    }

    @Override
    public String getFirstAttribute(String name) {
        return null;
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        return null;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return null;
    }

    @Override
    public Stream<String> getRequiredActionsStream() {
        return null;
    }

    @Override
    public void addRequiredAction(String action) {
        // No-op
    }

    @Override
    public void removeRequiredAction(String action) {
        // No-op
    }

    @Override
    public void addRequiredAction(RequiredAction action) {
        // No-op
    }

    @Override
    public void removeRequiredAction(RequiredAction action) {
        // No-op
    }

    @Override
    public boolean isEmailVerified() {
        return false;
    }

    @Override
    public void setEmailVerified(boolean verified) {
        // No-op
    }

    @Override
    public Stream<RoleModel> getRealmRoleMappingsStream() {
        return null;
    }

    @Override
    public Stream<RoleModel> getClientRoleMappingsStream(ClientModel app) {
        return null;
    }

    @Override
    public boolean hasRole(RoleModel role) {
        return false;
    }

    @Override
    public void grantRole(RoleModel role) {
        // No-op
    }

    @Override
    public Stream<RoleModel> getRoleMappingsStream() {
        return null;
    }

    @Override
    public void deleteRoleMapping(RoleModel role) {
        // No-op
    }

    @Override
    public String getFederationLink() {
        return null;
    }

    @Override
    public void setFederationLink(String link) {
        // No-op
    }

    @Override
    public String getServiceAccountClientLink() {
        return null;
    }

    @Override
    public void setServiceAccountClientLink(String clientInternalId) {
        // No-op
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return null;
    }

    @Override
    public Long getCreatedTimestamp() {
        return null;
    }

    @Override
    public void setCreatedTimestamp(Long timestamp) {
        // No-op
    }

    @Override
    public Stream<GroupModel> getGroupsStream() {
        return null;
    }

    @Override
    public void joinGroup(GroupModel group) {
        // No-op
    }

    @Override
    public void leaveGroup(GroupModel group) {
        // No-op
    }

    @Override
    public boolean isMemberOf(GroupModel group) {
        return false;
    }

    @Override
    public boolean equals(Object o) {
        // Usually, a no-op or a reference check. Customize as needed.
        return false;
    }

    @Override
    public int hashCode() {
        // Return a constant or implement some logic if needed
        return 1;
    }

    @Override
    public String getFirstName() {
        return null;
    }

    @Override
    public void setFirstName(String firstName) {
        // No-op
    }

    @Override
    public String getLastName() {
        return null;
    }

    @Override
    public void setLastName(String lastName) {
        // No-op
    }

    @Override
    public String getEmail() {
        // Return a fixed email, for demonstration
        return DEFAULT_EMAIL;
    }

    @Override
    public void setEmail(String email) {
        // No-op
    }

    @Override
    public String toString() {
        return "UserModelDefaultMethodsImpl [mock user model]";
    }
}
