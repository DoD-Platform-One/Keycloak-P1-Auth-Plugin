package dod.p1.kc.routing.redirects.runtime;

import org.jboss.logging.Logger;
import java.util.HashMap;
import java.util.Map;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

import javax.enterprise.context.ApplicationScoped;


@ApplicationScoped
public class KcRoutingRedirectsHandler implements Handler<RoutingContext> {

    /**
     * declare logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KcRoutingRedirectsHandler.class.getName());

    /**
     * the urlsMap.
     */
    private static HashMap<String, String> urlsMap = null;
    /**
     * the pathPrefixesMap.
     */
    private static HashMap<String, String> pathPrefixesMap = null;
    /**
     * the pathFiltersMap.
     */
    private static HashMap<String, String> pathFiltersMap = null;

    /**
      * @param map the map to test for Null or Empty
      * @return true if map is null or empty
     */
    public static boolean isNullOrEmptyMap(final Map<?, ?> map) {
        return (map == null || map.isEmpty());
    }

    /**
     *
     * @param rc the event to handle
     */
    @Override
    public void handle(final RoutingContext rc) {

      if (!isNullOrEmptyMap(urlsMap) && urlsMap.containsKey(rc.normalizedPath())) {
        LOGGER.debugf("Redirect Match: %s to %s", rc.normalizedPath(), urlsMap.get(rc.normalizedPath()));
        rc.redirect(urlsMap.get(rc.normalizedPath()));
      }

    if (!isNullOrEmptyMap(pathPrefixesMap)) {
      pathPrefixesMap.forEach((k, v) -> {
        if (rc.normalizedPath().startsWith(k)) {
            LOGGER.debugf("PathPrefixing Match: %s to %s", k, v);
            LOGGER.debugf("uri before: %s", rc.request().uri());
            rc.redirect(rc.request().uri().replace(k, v));
            LOGGER.debugf("uri after: %s", rc.request().uri().replace(k, v));
        }
      });
    }

    if (!isNullOrEmptyMap(pathFiltersMap) && pathFiltersMap.containsKey(rc.normalizedPath())) {
      LOGGER.debugf("Filters Match: %s to %s", rc.normalizedPath(), pathFiltersMap.get(rc.normalizedPath()));
      LOGGER.debugf("uri before: %s", rc.request().uri());

      if (rc.request().query() != null) {
          LOGGER.debugf("Routing to %s", (pathFiltersMap.get(rc.normalizedPath()) + "?" + rc.request().query()));
          rc.reroute(pathFiltersMap.get(rc.normalizedPath()) + "?" + rc.request().query());
      } else {
          LOGGER.debugf("Routing to %s", pathFiltersMap.get(rc.normalizedPath()));
          rc.reroute(pathFiltersMap.get(rc.normalizedPath()));
      }
    }
  }

    /**
     *
     * @param argUrlsMap
     */
    public static void setRedirectPaths(final Map<String, String> argUrlsMap) {
      LOGGER.debugf("KcRoutingRedirectsHandler: setRedirectPaths(%s) ", argUrlsMap);
      urlsMap = (HashMap<String, String>) argUrlsMap;
    }

    /**
     *
     * @param argpathPrefixesMap
     */
    public static void setPathPrefixes(final Map<String, String> argpathPrefixesMap) {
      LOGGER.debugf("KcRoutingRedirectsHandler: setPathPrefixes(%s) ", argpathPrefixesMap);
      pathPrefixesMap = (HashMap<String, String>) argpathPrefixesMap;
    }
    /**
     *
     * @param argpathFiltersMap
     */
    public static void setPathFilters(final Map<String, String> argpathFiltersMap) {
      LOGGER.debugf("KcRoutingRedirectsHandler: setPathFilters(%s) ", argpathFiltersMap);
      pathFiltersMap = (HashMap<String, String>) argpathFiltersMap;

    }

}
