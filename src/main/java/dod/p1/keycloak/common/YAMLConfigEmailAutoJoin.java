package dod.p1.keycloak.common;

import org.keycloak.models.GroupModel;

import java.util.List;

public class YAMLConfigEmailAutoJoin {

    /**
     * String for description.
     */
    private String description;
    /**
     * List of strings for goups.
     */
    private List<String> groups;
    /**
     * List of strings for domains.
     */
    private List<String> domains;
    /**
     * List of GroupModel.
     */
    private List<GroupModel> groupModels;

    /**
     * Get Description.
     * @return String
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set Description.
     * @param pDescription
     */
    public void setDescription(final String pDescription) {
        this.description = description;
    }

    /**
     * Get Groups.
     * @return List
     */
    public List<String> getGroups() {
        return groups;
    }

    /**
     * Set Groups.
     * @param pGroups
     */
    public void setGroups(final List<String> pGroups) {
        this.groups = groups;
    }

    /**
     * Get Domains.
     * @return List
     */
    public List<String> getDomains() {
        return domains;
    }

    /**
     * Set Domains.
     * @param pDomains
     */
    public void setDomains(final List<String> pDomains) {
        this.domains = domains;
    }

    /**
     * Get Group Models.
     * @return List
     */
    public List<GroupModel> getGroupModels() {
        return groupModels;
    }

    /**
     * Set Domains.
     * @param pGroupModels
     */
    public void setGroupModels(final List<GroupModel> pGroupModels) {
        this.groupModels = groupModels;
    }

}
