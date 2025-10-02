package dod.p1.keycloak.common;

import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.keycloak.Config;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import java.util.stream.Stream;
import org.keycloak.models.KeycloakSession;

public final class CommonConfig {

    /**
     * Concurrent map to store instances per realm.
     */
    private static final ConcurrentMap<String, CommonConfig> INSTANCES = new ConcurrentHashMap<>();

    /**
     * Default configuration file path.
     * This can be overridden by system property 'keycloak.customreg.config.path'
     */
    private static final String DEFAULT_CONFIG_FILE_PATH =
            System.getProperty("keycloak.customreg.config.path", "/opt/keycloak/conf/customreg.yaml");

    /**
     * YAML config variable.
     */
    private final YAMLConfig config;

    /**
     * List of GroupModel for auto join group x509.
     */
    private final List<GroupModel> autoJoinGroupX509;

    /**
     * List of GroupModel for no email match auto join group.
     */
    private final List<GroupModel> noEmailMatchAutoJoinGroup;

    /**
     * Common logger.
     */
    public static final Logger LOGGER_COMMON = LogManager.getLogger(CommonConfig.class);

    private CommonConfig(final KeycloakSession session, final RealmModel realm) {

        config = loadConfigFile();

        autoJoinGroupX509 = convertPathsToGroupModels(session, realm, config.getX509().getAutoJoinGroup());
        noEmailMatchAutoJoinGroup = convertPathsToGroupModels(session, realm, config.getNoEmailMatchAutoJoinGroup());

        config.getEmailMatchAutoJoinGroup().forEach(match -> {
            boolean hasInvalidDomain = match.getDomains().stream()
                    .anyMatch(domain -> domain.matches("^[^\\.\\@][\\w\\-\\.]+$"));
            if (hasInvalidDomain) {
                LOGGER_COMMON.warn(
                        "Invalid email domain config. All email domain matches should begin with a \".\" or \"@\".");
                match.setDomains(new ArrayList<>());
            } else {
                match.setGroupModels(convertPathsToGroupModels(session, realm, match.getGroups()));
            }
        });
    }

    /**
     * Get common config instance.
     *
     * @param session the Keycloak session
     * @param realm   the realm model
     * @return CommonConfig instance
     */
    public static CommonConfig getInstance(final KeycloakSession session, final RealmModel realm) {
        return INSTANCES.computeIfAbsent(realm.getName(), realmName -> new CommonConfig(session, realm));
    }

    private YAMLConfig loadConfigFile() {
        // Get the config file path from the env var, or from Keycloak config, or use a default
        String configFilePath = System.getenv("CUSTOM_REGISTRATION_CONFIG");
        if (configFilePath == null || configFilePath.isEmpty()) {
            Config.Scope scope = Config.scope("customRegistration");
            if (scope != null) {
                configFilePath = scope.get("configFilePath", DEFAULT_CONFIG_FILE_PATH);
            } else {
                configFilePath = DEFAULT_CONFIG_FILE_PATH;
            }
        }
        configFilePath = FilenameUtils.normalize(configFilePath);
        File file = NewObjectProvider.getFile(configFilePath);
        YAMLConfig yamlConfig;
        try (InputStream fileInputStream = NewObjectProvider.getFileInputStream(file)) {
            // Read the entire file into a byte array
            byte[] bytes = fileInputStream.readAllBytes();
            Yaml yaml = NewObjectProvider.getYaml();
            // Pass a fresh ByteArrayInputStream to the YAML loader
            yamlConfig = yaml.loadAs(new ByteArrayInputStream(bytes), YAMLConfig.class);
        } catch (IOException e) {
            LOGGER_COMMON.fatal("Invalid or missing YAML Config, aborting.", e);
            System.exit(1);
            return null;
        }
        return yamlConfig;
    }






    private List<GroupModel> convertPathsToGroupModels(
        final KeycloakSession session,
        final RealmModel realm,
        final List<String> paths) {

        List<GroupModel> groupModels = new ArrayList<>();

        for (String groupPath : paths) {
            GroupModel group = KeycloakModelUtils.findGroupByPath(session, realm, groupPath);

            if (group != null) {
                groupModels.add(group);
            } else {
                LOGGER_COMMON.warn("Group path {} does not exist in realm {}", groupPath, realm.getName());
            }
        }

        return groupModels;
    }

    /**
     * Get email match auto join group.
     *
     * @return Stream of YAMLConfigEmailAutoJoin
     */
    public Stream<YAMLConfigEmailAutoJoin> getEmailMatchAutoJoinGroup() {
        return config
                .getEmailMatchAutoJoinGroup()
                .stream()
                .filter(group -> !group.getDomains().isEmpty());
    }

    /**
     * Get user identity attribute.
     *
     * @param realm the realm model
     * @return String attribute name
     */
    public String getUserIdentityAttribute(final RealmModel realm) {
        String multiRealmEnabled = "false";
        Config.Scope scope = Config.scope("multiRealm");
        if (scope != null) {
            multiRealmEnabled = scope.get("enabled", "false");
        }

        if (multiRealmEnabled.equals("true") && !realm.getName().equals("baby-yoda")) {
            return config.getX509().getUserIdentityAttribute() + "_" + realm.getName();
        }

        return config.getX509().getUserIdentityAttribute();
    }

    /**
     * Get user active 509 attribute.
     *
     * @return String attribute name
     */
    public String getUserActive509Attribute() {
        return config.getX509().getUserActive509Attribute();
    }

    /**
     * Get auto join group x509.
     *
     * @return Stream of GroupModel
     */
    public Stream<GroupModel> getAutoJoinGroupX509() {
        return autoJoinGroupX509.stream();
    }

    /**
     * Get required certificate policies.
     *
     * @return Stream of String policies
     */
    public Stream<String> getRequiredCertificatePolicies() {
        return config.getX509().getRequiredCertificatePolicies().stream();
    }

    /**
     * Get no email match auto join group.
     *
     * @return Stream of GroupModel
     */
    public Stream<GroupModel> getNoEmailMatchAutoJoinGroup() {
        return noEmailMatchAutoJoinGroup.stream();
    }

    /**
     * Get client login attributes configuration.
     *
     * @return List of YAMLConfigClientLogin
     */
    public List<YAMLConfigClientLogin> getClientLoginAttributes() {
        return config.getClientLoginAttributes();
    }

    /**
     * Get ignored group protection clients.
     *
     * @return List of String client names
     */
    public List<String> getIgnoredGroupProtectionClients() {
        return config.getGroupProtectionIgnoreClients();
    }

    static void clearInstances() {
        INSTANCES.clear();
    }

}
