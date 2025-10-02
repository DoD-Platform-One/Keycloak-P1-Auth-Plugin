package dod.p1.keycloak.common;

import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * YAML configuration class for client-specific login tracking.
 */
@NoArgsConstructor
public class YAMLConfigClientLogin {

    /**
     * String for attribute name.
     */
    @Getter
    @Setter
    private String attributeName;

    /**
     * List of client IDs to track for this attribute.
     */
    @Getter
    @Setter
    private List<String> clientIds;

    /**
     * Optional description for this configuration.
     */
    @Getter
    @Setter
    private String description;
}
