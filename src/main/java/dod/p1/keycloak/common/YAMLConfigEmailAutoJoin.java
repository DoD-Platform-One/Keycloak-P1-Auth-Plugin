package dod.p1.keycloak.common;

import java.util.List;

import org.keycloak.models.GroupModel;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
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
     * Lsit of GroupModel.
     */
    private List<GroupModel> groupModels;
}
