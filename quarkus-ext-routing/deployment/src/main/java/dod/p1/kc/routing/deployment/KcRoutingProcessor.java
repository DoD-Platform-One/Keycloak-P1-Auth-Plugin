package dod.p1.kc.routing.deployment;
import dod.p1.kc.routing.runtime.KcRoutingRecorder;

import java.util.HashMap;
import java.util.Map;

import java.util.stream.Collectors;
import org.jboss.logging.Logger;

import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.vertx.http.deployment.NonApplicationRootPathBuildItem;
import io.quarkus.vertx.http.deployment.RouteBuildItem;

public class KcRoutingProcessor {

    /**
     * Define logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KcRoutingProcessor.class);

    /**
     * Name of feature required for quarkus build augmentation phase.
     */
    private static final String FEATURE = "kc-routing";

  /**
   * Path delimiter.
   */
  private static final String PATH_DELIMITER = "/";

    /**
     *
     * @return newFeatureBuildItem()
     */
    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    /**
     *
     * @param recorder
     * @param routes
     * @param nonApplicationRootPathBuildItem
     * @param kcRoutingConfig
     */
    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    public void registerKcRoutingHandler(final KcRoutingRecorder recorder,
            final BuildProducer<RouteBuildItem> routes,
            final NonApplicationRootPathBuildItem nonApplicationRootPathBuildItem,
            final KcRoutingConfig kcRoutingConfig) {

        HashMap<String, String> pathRedirectsMap = new HashMap<>(kcRoutingConfig.pathRedirect);
        HashMap<String, String> pathPrefixesMap = new HashMap<>(kcRoutingConfig.pathPrefix);
        HashMap<String, String> pathFiltersMap = new HashMap<>(kcRoutingConfig.pathFilter);
        HashMap<String, String> pathBlocksMap = new HashMap<>(kcRoutingConfig.pathBlock);
        HashMap<String, String> pathRecursiveBlocksMap = new HashMap<>(kcRoutingConfig.pathRecursiveBlock);
        HashMap<String, String> pathAllowsMap = new HashMap<>(kcRoutingConfig.pathAllow);

        pathRedirectsMap.forEach((k, v) -> {
          LOGGER.infof("Creating Redirect Routes: %s %s", k, v);
          routes.produce(nonApplicationRootPathBuildItem.routeBuilder()
                  .orderedRoute(k, 1)
                  .handler(recorder.getHandler())
                  .build());
        });
        recorder.setPathRedirects(pathRedirectsMap);

        pathPrefixesMap.forEach((k, v) -> {
          LOGGER.infof("Creating Prefix Routes: %s %s", k, v);
          routes.produce(nonApplicationRootPathBuildItem.routeBuilder()
                  .orderedRoute(k + "/*", 1)
                  .handler(recorder.getHandler())
                  .build());
        });
        recorder.setPathPrefixes(pathPrefixesMap);

        pathFiltersMap.forEach((k, v) -> {
          LOGGER.infof("Creating Filter Routes: %s %s", k, v);
          routes.produce(nonApplicationRootPathBuildItem.routeBuilder()
                  .orderedRoute(k, 1)
                  .handler(recorder.getHandler())
                  .build());
        });
        recorder.setPathFilters(pathFiltersMap);

        // orderedRoute() does not route paths without a leading slash if specified with one
        // But the block handler needs a slash to deliminate /test1 from /test11
        // Below code scripts off slashes from all quarkus configs
        // and after adding routes adds them back for handler.
        // Handler adds slashes to all incoming requests before parsing
        pathBlocksMap = pathBlocksMap.entrySet()
          .stream()
          .collect(Collectors.toMap(
                    e -> e.getKey().endsWith("/") ? e.getKey().substring(0, e.getKey().length() - 1) : e.getKey(),
                    Map.Entry::getValue, (prev, next) -> next, HashMap::new)
                    );
        pathBlocksMap.forEach((k, v) -> {
          LOGGER.infof("Creating Block Routes: %s %s", k, v);
          routes.produce(nonApplicationRootPathBuildItem.routeBuilder()
                  .orderedRoute(k, 1)
                  .handler(recorder.getHandler())
                  .build());
        });
        pathBlocksMap = pathBlocksMap.entrySet()
          .stream()
          .collect(Collectors.toMap(
                    e -> e.getKey().endsWith("/") ? e.getKey() : e.getKey() + PATH_DELIMITER,
                    Map.Entry::getValue, (prev, next) -> next, HashMap::new)
                    );
        recorder.setPathBlocks(pathBlocksMap);

        pathRecursiveBlocksMap = pathRecursiveBlocksMap.entrySet()
          .stream()
          .collect(Collectors.toMap(
                    e -> e.getKey().endsWith("/") ? e.getKey() : e.getKey() + PATH_DELIMITER,
                    Map.Entry::getValue, (prev, next) -> next, HashMap::new)
                    );
        pathRecursiveBlocksMap.forEach((k, v) -> {
          LOGGER.infof("Creating Recursive Block Routes: %s %s", k, v);
          routes.produce(nonApplicationRootPathBuildItem.routeBuilder()
                  .orderedRoute(k + "*", 1)
                  .handler(recorder.getHandler())
                  .build());
        });
        recorder.setPathRecursiveBlocks(pathRecursiveBlocksMap);

        pathAllowsMap = pathAllowsMap.entrySet()
          .stream()
          .collect(Collectors.toMap(
                    e -> e.getKey().endsWith("/") ? e.getKey() : e.getKey() + PATH_DELIMITER,
                    Map.Entry::getValue, (prev, next) -> next, HashMap::new)
                    );
        pathAllowsMap.forEach((k, v) -> LOGGER.infof("Creating Allow Rules: %s %s", k, v));
        recorder.setPathAllows(pathAllowsMap);
  }
}
