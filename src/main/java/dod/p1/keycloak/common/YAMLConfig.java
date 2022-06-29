package dod.p1.keycloak.common;

import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
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

}
