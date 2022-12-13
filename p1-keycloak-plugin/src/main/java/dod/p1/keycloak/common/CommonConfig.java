package dod.p1.keycloak.common;

import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.System.exit;
import static org.keycloak.models.utils.KeycloakModelUtils.findGroupByPath;


public final class CommonConfig {

    /**
     * common config.
     */
    private static CommonConfig instance;
    /**
     * yaml config variable.
     */
    private final YAMLConfig config;
    /**
     * List of GroupModel for auto join group x509.
     */
    private final List<GroupModel> autoJoinGroupX509;
    /**
     * List of GroupModel for no email matchauto join group.
     */
    private final List<GroupModel> noEmailMatchAutoJoinGroup;
    /**
     * common logger.
     */
    public static final Logger LOGGER_COMMON = LogManager.getLogger(CommonConfig.class);

    private CommonConfig(final RealmModel realm) {

        config = loadConfigFile();

        autoJoinGroupX509 = convertPathsToGroupModels(realm, config.getX509().getAutoJoinGroup());
        noEmailMatchAutoJoinGroup = convertPathsToGroupModels(realm, config.getNoEmailMatchAutoJoinGroup());

        config.getEmailMatchAutoJoinGroup().forEach(match -> {
            boolean hasInvalidDomain = match.getDomains().stream()
                    .anyMatch(domain -> domain.matches("^[^\\.\\@][\\w\\-\\.]+$"));
            if (hasInvalidDomain) {
                LOGGER_COMMON.warn(
                        "Invalid email domain config.  All email domain matches should begin with a \".\" or \"@\".");
                match.setDomains(new ArrayList<>());
            } else {
                match.setGroupModels(convertPathsToGroupModels(realm, match.getGroups()));
            }
        });
    }

    /**
     * get common config instance.
     * @param realm
     * @return CommonConfig
     */
    public static CommonConfig getInstance(final RealmModel realm) {
        if (instance == null) {
            instance = new CommonConfig(realm);
        }

        return instance;
    }

    private YAMLConfig loadConfigFile() {
        String configFilePath = FilenameUtils.normalize(System.getenv("CUSTOM_REGISTRATION_CONFIG"));
        File file = NewObjectProvider.getFile(configFilePath);
        YAMLConfig yamlConfig;

        try (
                FileInputStream fileInputStream = NewObjectProvider.getFileInputStream(file);
            ) {
            Yaml yaml = NewObjectProvider.getYaml();
            yamlConfig = yaml.load(fileInputStream);
        } catch (IOException e) {
            LOGGER_COMMON.fatal("Invalid or missing YAML Config, aborting.");
            exit(1);
            return null;
        }

        return yamlConfig;
    }

    private List<GroupModel> convertPathsToGroupModels(final RealmModel realm, final List<String> paths) {
        return paths
                .stream()
                .map(group -> findGroupByPath(realm, group))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /**
     * get email match auto join group.
     * @return Stream<YAMLConfigEmailAutoJoin>
     */
    public Stream<YAMLConfigEmailAutoJoin> getEmailMatchAutoJoinGroup() {
        return config
                .getEmailMatchAutoJoinGroup()
                .stream()
                .filter(group -> !group.getDomains().isEmpty());
    }

    /**
     * get user identity attribute.
     * @return String
     */
    public String getUserIdentityAttribute() {
        return config.getX509().getUserIdentityAttribute();
    }

    /**
     * get user active 509 attribute.
     * @return String
     */
    public String getUserActive509Attribute() {
        return config.getX509().getUserActive509Attribute();
    }

    /**
     * get auto join group x509.
     * @return Stream<GroupModel>
     */
    public Stream<GroupModel> getAutoJoinGroupX509() {
        return autoJoinGroupX509.stream();
    }

    /**
     * get required certificate policies.
     * @return Stream<String>
     */
    public Stream<String> getRequiredCertificatePolicies() {
        return config.getX509().getRequiredCertificatePolicies().stream();
    }

    /**
     * get no email match auto join group.
     * @return Stream<GroupModel>
     */
    public Stream<GroupModel> getNoEmailMatchAutoJoinGroup() {
        return noEmailMatchAutoJoinGroup.stream();
    }

    /**
     * get ignored group proetection clients.
     * @return List<String>
     */
    public List<String> getIgnoredGroupProtectionClients() {
        return config.getGroupProtectionIgnoreClients();
    }

}
