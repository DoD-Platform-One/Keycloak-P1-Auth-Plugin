package dod.p1.keycloak.common;

import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
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

}
