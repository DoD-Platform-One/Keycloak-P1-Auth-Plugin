package dod.p1.kc.routing.runtime;

import org.jboss.logging.Logger;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

import jakarta.enterprise.context.ApplicationScoped;
import org.springframework.security.web.util.matcher.IpAddressMatcher;


@ApplicationScoped
public class KcRoutingHandler implements Handler<RoutingContext> {

    /**
     * declare logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KcRoutingHandler.class.getName());

    /**
     * the pathRedirectsMap.
     */
    private static HashMap<String, String> pathRedirectsMap = null;
    /**
     * the pathPrefixesMap.
     */
    private static HashMap<String, String> pathPrefixesMap = null;
    /**
     * the pathFiltersMap.
     */
    private static HashMap<String, String> pathFiltersMap = null;
    /**
     * the pathBlocksMap.
     */
    private static HashMap<String, String> pathBlocksMap = null;
    /**
     * the pathRecursiveBlocksMap.
     */
    private static HashMap<String, String> pathRecursiveBlocksMap = null;
    /**
     * the pathAllowsMap.
     */
    private static HashMap<String, String> pathAllowsMap = null;
    /**
     * the HTTP_BAD_REQUEST.
     */
    public static final int HTTP_BAD_REQUEST = 400;
    /**
     * the HTTP_NOT_FOUND.
     */
    public static final int HTTP_NOT_FOUND = 404;

    /**
      * @param map the map to test for Null or Empty
      * @return true if map is null or empty
     */
    private static boolean isNullOrEmptyMap(final Map<?, ?> map) {
        return (map == null || map.isEmpty());
    }
    /**
      * @param argPath
      * @return Path without slash
     */
    private static String addTrailingSlash(final String argPath) {
      if (argPath.endsWith("/")) {
        return argPath;
      } else {
        return argPath + '/';
      }
    }
    /**
     *
     * @param rc the event to handle
     */
    @Override
    public void handle(final RoutingContext rc) {

      //Enable when adding new code for more debug output
      if (LOGGER.isDebugEnabled()) {
        debugHTTPHeaders(rc);
      }
      pathRedirectsHandler(rc);
      pathPrefixesHandler(rc);
      pathFiltersHandler(rc);
      pathBlocksHandler(rc);
      pathRecursiveBlocksHandler(rc);
    }
    /**
     * Check if IP is within CIDR range.
     * @param  ip
     * @param  subnet
     * @return true if ip matches CIDR false if not
     */
    private static boolean ipMatchesSubnet(final String ip, final String subnet) {
      //Option 2 allows us to bring in IpAddressMatcher class if we don't want to use dependency
      //Link below should be put back together: https://stackoverflow.com/questions/577363/
      //how-to-check-if-an-ip-address-is-from-a-particular-network-netmask-in-java
      IpAddressMatcher ipAddressMatcher = new IpAddressMatcher(subnet);
      return ipAddressMatcher.matches(ip);
    }
    /**
     * Debug output used for troubleshooting HTTP Headers.
     * @param rc
     */
    private static void debugHTTPHeaders(final RoutingContext rc) {
      // Host = https for https and either http or none for http traffic
      //https://vertx.io/docs/apidocs/io/vertx/core/http/HttpServerRequest.html
      LOGGER.debugf("Uri %s", rc.request().uri());
      LOGGER.debugf("NormalizedPath: %s", rc.normalizedPath());
      LOGGER.debugf("Path  %s", rc.request().path());
      LOGGER.debugf("Query: %s", rc.request().query());
      LOGGER.debugf("Remote Address: %s", rc.request().remoteAddress());
      LOGGER.debugf("local Address: %s", rc.request().localAddress());
      LOGGER.debugf("Method: %s", rc.request().method());
      LOGGER.debugf("Host:  %s", rc.request().host());
      LOGGER.debugf("isSSL: %s", rc.request().isSSL());
    }
    /**
     * Handler for Redirects processing.
     * @param rc
     */
    private static void pathRedirectsHandler(final RoutingContext rc) {
      LOGGER.debugf("KcRoutingHandler::PathRedirectsHandler(%s)", rc.normalizedPath());
      if (!isNullOrEmptyMap(pathRedirectsMap) && pathRedirectsMap.containsKey(rc.normalizedPath())) {
        LOGGER.debugf("Redirect Match: %s to %s", rc.normalizedPath(), pathRedirectsMap.get(rc.normalizedPath()));
        rc.redirect(pathRedirectsMap.get(rc.normalizedPath()));
      }
    }
    /**
     * Handler for Prefixes processing.
     * @param rc
     */
    private static void pathPrefixesHandler(final RoutingContext rc) {
      LOGGER.debugf("KcRoutingHandler::PathPrefixesHandler(%s)", rc.normalizedPath());
      if (!isNullOrEmptyMap(pathPrefixesMap)) {
        pathPrefixesMap.forEach((k, v) -> {
          if (rc.normalizedPath().startsWith(k)) {
              LOGGER.debugf("Prefix Match: %s to %s", k, v);
              LOGGER.debugf("uri before: %s", rc.request().uri());
              rc.redirect(rc.request().uri().replace(k, v));
              LOGGER.debugf("uri after: %s", rc.request().uri().replace(k, v));
          }
        });
      }
    }
    /**
     * Handler for Fiilters processing.
     * @param rc
     */
    private static void pathFiltersHandler(final RoutingContext rc) {
      LOGGER.debugf("KcRoutingHandler::PathFiltersHandler(%s)", rc.normalizedPath());
      if (!isNullOrEmptyMap(pathFiltersMap) && pathFiltersMap.containsKey(rc.normalizedPath())) {
        LOGGER.debugf("Filter Match: %s to %s", rc.normalizedPath(), pathFiltersMap.get(rc.normalizedPath()));
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
     * Handler for Blocks processing.
     * @param rc
     */
    private static void pathBlocksHandler(final RoutingContext rc) {
      String path = addTrailingSlash(rc.normalizedPath());
      LOGGER.debugf("KcRoutingHandler::PathBlocksHandler(%s)", path);
      if (!isNullOrEmptyMap(pathBlocksMap) && pathBlocksMap.containsKey(path)) {

        if (LOGGER.isDebugEnabled()) {
          LOGGER.debugf("Block Match on Path %s to Key %s checking if port matches.",
            path, pathBlocksMap.get(path));

          if (!isNullOrEmptyMap(pathAllowsMap) && pathAllowsMap.containsKey(path)) {
            LOGGER.debugf("Allow Match on Path %s checking Value/CIDR for match to %s",
            path, pathAllowsMap.get(path));
          }
        }

        if (!pathAllowsHandler(rc)) {
          // There is not an allow list to cross reference
          // Below keeps ports as strings
          String localPort = String.valueOf(rc.request().localAddress().port());
          String[] portsStringArray = pathBlocksMap.get(path).split(",");
          List<String> portsList = Arrays.asList(portsStringArray);

          LOGGER.debugf("Blacklisted Ports: %s", portsList);

          if (portsList.contains(localPort)) {
              LOGGER.debugf("Port Match! Blocking Route on port %s", localPort);
              rc.response().setStatusCode(HTTP_BAD_REQUEST).end("<html><body><h1>Resource Blocked</h1></body></html>");
          } else {
              LOGGER.debugf("Allowing Routing %s to next hop", path);
              rc.next();
          }
        }
      }
    }
    /**
     * Handler for Blocks processing.
     * @param rc
     */
    private static void pathRecursiveBlocksHandler(final RoutingContext rc) {
      String path = addTrailingSlash(rc.normalizedPath());
      LOGGER.debugf("KcRoutingHandler::pathRecursiveBlocksHandler(%s)", path);

      if (!isNullOrEmptyMap(pathRecursiveBlocksMap)) {
        pathRecursiveBlocksMap.forEach((k, v) -> {
          if (path.equals(k) || path.startsWith(k)) {
            loggingPathRecursiveBlocksHandler(path, k);
            if (!pathAllowsHandlerForRecursiveBlock(rc)) {
              processPathRecursiveBlocksHandler(rc, path);
            }
          }
        });
      }
    }
    /**
     * Processor for Recursive Blocks Handler.
     * @param rc
     * @param path
     */
    private static void processPathRecursiveBlocksHandler(final RoutingContext rc, final String path) {
      String localPort = String.valueOf(rc.request().localAddress().port());
      pathRecursiveBlocksMap.forEach((k2, v2) -> {
        if (path.equals(k2) || path.startsWith(k2)) {
          String[] portsStringArray = v2.split(",");
          List<String> portsList = new ArrayList<>();
          portsList = Arrays.asList(portsStringArray);

          LOGGER.debugf("Blacklisted Ports: %s", portsList);

          if (portsList.contains(localPort)) {
              LOGGER.debugf("Port match, Blocking Route on Port %s", localPort);
              rc.response().setStatusCode(HTTP_BAD_REQUEST)
                .end("<html><body><h1>Resource Blocked</h1></body></html>");
          } else {
              LOGGER.debugf("Allowing Route %s to next hop", path);
              rc.next();
          }
        }
      });
    }
    /**
     * Logging for Recursive Blocks Handler.
     * @param path
     * @param k
     */
    private static void loggingPathRecursiveBlocksHandler(final String path, final String k) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debugf("Recursive Block Match on Path %s to Key %s checking if port matches.",
                path, k);
        if (!isNullOrEmptyMap(pathAllowsMap)) {
          pathAllowsMap.forEach((k2, v2) -> {
            if (path.equals(k2) || path.startsWith(k2 + '/')) {
              LOGGER.debugf("Allow Match on Path %s to Key %s checking Value/CIDR for match to %s",
                      path, k2, v2);
            }
          });
        }
      }
    }
    /**
     * Handler for Allows processing.
     * @param rc
     * @return true if allow match false if no match
     */
    private static boolean pathAllowsHandler(final RoutingContext rc) {
      String path = addTrailingSlash(rc.normalizedPath());
      LOGGER.debugf("KcRoutingHandler::pathAllowsHandler(%s)", path);

      // There is an allow list to cross reference
      if (!isNullOrEmptyMap(pathAllowsMap)
        && pathAllowsMap.containsKey(path)
        && rc.request().localAddress().hostAddress() != null) {

        String hostAddress = rc.request().localAddress().hostAddress();
        String[] allowedCIDRs = pathAllowsMap.get(path).split(",");
        List<String> allowedCIDRsList = Arrays.asList(allowedCIDRs);
        LOGGER.debugf("Whitelisted CIDRs: %s", allowedCIDRsList);
        for (String i : allowedCIDRsList) {
          if (ipMatchesSubnet(hostAddress, i)) {
              LOGGER.debugf("Allow Match Found %s Routing %s to next hop", i, path);
              rc.next();
              return true;
          }
        }
      }
      return false;
    }
    /**
     * Handler for Allows processing used with PathRecursiveBlocks.
     * @param rc
     * @return true if allow match false if no match
     */
    private static boolean pathAllowsHandlerForRecursiveBlock(final RoutingContext rc) {
      String path = addTrailingSlash(rc.normalizedPath());
      LOGGER.debugf("KcRoutingHandler::pathAllowsHandlerForRecursiveBlock(%s)", path);

      // There is an allow list to cross reference
      if (!isNullOrEmptyMap(pathAllowsMap)
        && rc.request().localAddress().hostAddress() != null) {

        String hostAddress = rc.request().localAddress().hostAddress();
        for (Map.Entry<String, String> entry : pathAllowsMap.entrySet()) {
          if (path.equals(entry.getKey()) || path.startsWith(entry.getKey())) {
            String[] allowedCIDRs = entry.getValue().split(",");
            List<String> allowedCIDRsList = Arrays.asList(allowedCIDRs);
            LOGGER.debugf("Whitelisted CIDRs: %s", allowedCIDRsList);
            return (matchFoundInCIDRsList(rc, hostAddress, allowedCIDRsList));
          }
        }
      }
      return false;
    }
    /**
       * Matches IPs to CIDRs.
       * @param rc
       * @param  hostAddress
       * @param  allowedCIDRsList
       * @return true if allow match false if no match
    */
    private static boolean matchFoundInCIDRsList(
      final RoutingContext rc, final String hostAddress, final List<String> allowedCIDRsList) {

      for (String i : allowedCIDRsList) {
        if (ipMatchesSubnet(hostAddress, i)) {
          LOGGER.debugf("Allow Match Found %s Routing %s to next hop", i, rc.normalizedPath());
          rc.next();
          return true;
        }
      }
      return false;
    }
    /**
     *
     * @param argpathRedirectsMap
     */
    public static void setPathRedirects(final Map<String, String> argpathRedirectsMap) {
      LOGGER.debugf("KcRoutingHandler::setPathRedirects(%s)", argpathRedirectsMap);
      pathRedirectsMap = (HashMap<String, String>) argpathRedirectsMap;
    }
    /**
     *
     * @param argpathPrefixesMap
     */
    public static void setPathPrefixes(final Map<String, String> argpathPrefixesMap) {
      LOGGER.debugf("KcRoutingHandler::setPathPrefixes(%s)", argpathPrefixesMap);
      pathPrefixesMap = (HashMap<String, String>) argpathPrefixesMap;
    }
    /**
     *
     * @param argpathFiltersMap
     */
    public static void setPathFilters(final Map<String, String> argpathFiltersMap) {
      LOGGER.debugf("KcRoutingHandler::setPathFilters(%s)", argpathFiltersMap);
      pathFiltersMap = (HashMap<String, String>) argpathFiltersMap;
    }
    /**
     *
     * @param argPathBlocksMap
     */
    public static void setPathBlocks(final Map<String, String> argPathBlocksMap) {
      LOGGER.debugf("KcRoutingHandler::setPathBlocks(%s)", argPathBlocksMap);
      pathBlocksMap = (HashMap<String, String>) argPathBlocksMap;
    }
    /**
     *
     * @param argPathRecursiveBlocksMap
     */
    public static void setPathRecursiveBlocks(final Map<String, String> argPathRecursiveBlocksMap) {
      LOGGER.debugf("KcRoutingHandler::setPathRecursiveBlocks(%s)", argPathRecursiveBlocksMap);
      pathRecursiveBlocksMap = (HashMap<String, String>) argPathRecursiveBlocksMap;
    }
    /**
     *
     * @param argPathAllowsMap
     */
    public static void setPathAllows(final Map<String, String> argPathAllowsMap) {
      LOGGER.debugf("KcRoutingHandler::setPathAllows(%s)", argPathAllowsMap);
      pathAllowsMap = (HashMap<String, String>) argPathAllowsMap;
    }
}
