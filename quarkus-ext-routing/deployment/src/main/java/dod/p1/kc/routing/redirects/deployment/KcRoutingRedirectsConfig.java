package dod.p1.kc.routing.redirects.deployment;

import java.util.Map;

import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

//https://quarkus.io/guides/config-mappings
@ConfigRoot
public class KcRoutingRedirectsConfig {
    /**
     * The path where KC Redirects is available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem
    //CHECKSTYLE:OFF
    Map<String, String> urls;
    //CHECKSTYLE:ON

    /**
     * The path where KC Prefixes Redirects are available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathPrefixes;
    //CHECKSTYLE:ON

    /**
     * The path where KC filters is available.
     * <p>
     * The value `/` is not allowed as it blocks the application from serving anything else.
     * By default, this value will be resolved as a path relative to `${quarkus.http.non-application-root-path}`.
     */
    @ConfigItem()
    //CHECKSTYLE:OFF
    Map<String, String> pathFilters;
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
