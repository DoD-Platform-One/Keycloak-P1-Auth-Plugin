package dod.p1.keycloak.common;

import java.util.List;


public class YAMLConfig {

    /**
     * Yaml config x509.
     */
    private YAMLConfigX509 x509;

    /**
     * List of strings for group protection ignore clients.
     */
    private List<String> groupProtectionIgnoreClients;

    /**
     * List of strings for no email match auto join group.
     */
    private List<String> noEmailMatchAutoJoinGroup;

    /**
     * List of YAMLConfigEmailAutoJoin objects.
     */
    private List<YAMLConfigEmailAutoJoin> emailMatchAutoJoinGroup;

    /**
     * Constructor.
     * @param pX509
     */
    public YAMLConfig(final YAMLConfigX509 pX509) {
        this.x509 = pX509;
    }

    /**
     * Get yaml config x509.
     * @return YAMLConfigX509
     */
    public YAMLConfigX509 getX509() {
        return x509;
    }

    /**
     * Set x509.
     * @param pX509
     */
    public void setX509(final YAMLConfigX509 pX509) {
        this.x509 = x509;
    }

    /**
     * Get Group Protection Ignore Clients.
     * @return List
     */
    public List<String> getGroupProtectionIgnoreClients() {
        return groupProtectionIgnoreClients;
    }

    /**
     * Set GroupProtectionIgnoreClients.
     * @param pGroupProtectionIgnoreClients
     */
    public void setGroupProtectionIgnoreClients(final List<String> pGroupProtectionIgnoreClients) {
        this.groupProtectionIgnoreClients = groupProtectionIgnoreClients;
    }

    /**
     * Get No Email Match Auto Join Group.
     * @return List
     */
    public List<String> getNoEmailMatchAutoJoinGroup() {
        return noEmailMatchAutoJoinGroup;
    }

    /**
     * Set No Email Match Auto Join Group.
     * @param pNoEmailMatchAutoJoinGroup
     */
    public void setNoEmailMatchAutoJoinGroup(final List<String> pNoEmailMatchAutoJoinGroup) {
        this.noEmailMatchAutoJoinGroup = noEmailMatchAutoJoinGroup;
    }

    /**
     * Get Email Match Auto Join Group.
     * @return List
     */
    public List<YAMLConfigEmailAutoJoin> getEmailMatchAutoJoinGroup() {
        return emailMatchAutoJoinGroup;
    }

    /**
     * Set Email Match Auto Join Group.
     * @param pEmailMatchAutoJoinGroup
     */
    public void setEmailMatchAutoJoinGroup(final List<YAMLConfigEmailAutoJoin> pEmailMatchAutoJoinGroup) {
        this.emailMatchAutoJoinGroup = emailMatchAutoJoinGroup;
    }
}
