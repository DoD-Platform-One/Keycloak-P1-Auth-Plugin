package dod.p1.kc.routing.deployment;

import java.util.Map;

import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

//https://quarkus.io/guides/config-mappings
@ConfigRoot
public class KcRoutingConfig {
    /**
     * The path where KC Redirects is available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem
    //CHECKSTYLE:OFF
    Map<String, String> pathRedirect;
    //CHECKSTYLE:ON

    /**
     * The path where KC Prefixes Redirects are available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathPrefix;
    //CHECKSTYLE:ON

    /**
     * The path where KC filters is available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathFilter;
    //CHECKSTYLE:ON

    /**
     * Map of dest ports to uri paths to block, but absolute, not recursive.
     * <p>
     * Example: Block /metrics on port 8443 - quarkus.kc-routing.path-block.8443=/metrics
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathBlock;
    //CHECKSTYLE:ON

    /**
     * Map of dest ports to uri paths to block recursively
     * <p>
     * Example: Block /metrics on port 8443 - quarkus.kc-routing.path-recursive-block.8443=/metrics
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathRecursiveBlock;
    //CHECKSTYLE:ON

    /**
     * Map of source IPs to uri paths to allow superseding blocks.
     * <p>
     * Example: Allow /metrics on for source CIDR 10.42.0.0 - quarkus.kc-routing.path-block.8443=/metrics
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathAllow;
    //CHECKSTYLE:ON

    /**
     * If this should be included every time. By default, this is only included when the application is running
     * in dev mode.
     */
    @ConfigItem(defaultValue = "false")
    //CHECKSTYLE:OFF
    boolean alwaysInclude;
    //CHECKSTYLE:ON
}
