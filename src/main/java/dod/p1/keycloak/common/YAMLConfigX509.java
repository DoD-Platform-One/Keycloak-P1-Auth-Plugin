package dod.p1.keycloak.common;

import java.util.List;


public class YAMLConfigX509 {

    /**
     * String for user identity attribute.
     */
    private String userIdentityAttribute;
    /**
     * String for user active 509 attribute.
     */
    private String userActive509Attribute;
    /**
     * List of strings for auto join group.
     */
    private List<String> autoJoinGroup;

    /**
     * List of strings required certificate policies.
     */
    private List<String> requiredCertificatePolicies;

    /**
     * Get user identity attribute.
     * @return String user identity attribute
     */
    public String getUserIdentityAttribute() {
        return userIdentityAttribute;
    }

    /**
     * Get user active 509 attribute.
     * @return String
     */
    public String getUserActive509Attribute() {
        return userActive509Attribute;
    }

    /**
     * Set user active 509 attribute.
     * @param pUserActive509Attribute
     */
    public void setUserActive509Attribute(final String pUserActive509Attribute) {
        this.userActive509Attribute = userActive509Attribute;
    }

    /**
     * Get auto join group.
     * @return List
     */
    public List<String> getAutoJoinGroup() {
        return autoJoinGroup;
    }

    /**
     * Set auto join group.
     * @param pAutoJoinGroup
     */
    public void setAutoJoinGroup(final List<String> pAutoJoinGroup) {
        this.autoJoinGroup = autoJoinGroup;
    }

    /**
     * Get require certificate policies.
     * @return List
     */
    public List<String> getRequiredCertificatePolicies() {
        return requiredCertificatePolicies;
    }

    /**
     * Set required certificate policies.
     * @param pRequiredCertificatePolicies
     */
    public void setRequiredCertificatePolicies(final List<String> pRequiredCertificatePolicies) {
        this.requiredCertificatePolicies = requiredCertificatePolicies;
    }
}
