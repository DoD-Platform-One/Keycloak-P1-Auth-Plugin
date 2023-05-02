package dod.p1.kc.routing.runtime;

import io.quarkus.runtime.annotations.Recorder;
import org.jboss.logging.Logger;
import java.util.Map;

@Recorder
public class KcRoutingRecorder {

    /**
     * Declare logger.
     */
    private static final Logger LOGGER = Logger.getLogger(KcRoutingRecorder.class.getName());

    //CHECKSTYLE:OFF
    KcRoutingHandler handler;
    //CHECKSTYLE:ON

    /**
     *
     * @return handler
     */
    public KcRoutingHandler getHandler() {
        if (handler == null) {
            LOGGER.debug("KcRoutingRecorder::getHandler() Creating new handle");
            handler = new KcRoutingHandler();
            return handler;
        } else {
          LOGGER.debug("KcRoutingRecorder::getHandler() Returning existing handle");
          return handler;
        }

    }
    /**
     *
     * @param argPathRedirectsMap
     */
    public void setPathRedirects(final Map<String, String> argPathRedirectsMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathRedirects(%s) ", argPathRedirectsMap);
      if (handler != null) {
        KcRoutingHandler.setPathRedirects(argPathRedirectsMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathRedirects(null)");
      }
    }

    /**
     *
     * @param argPathPrefixesMap
     */
    public void setPathPrefixes(final Map<String, String> argPathPrefixesMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathPrefixes(%s) ", argPathPrefixesMap);
      if (handler != null) {
        KcRoutingHandler.setPathPrefixes(argPathPrefixesMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathPrefixes(null)");
      }
    }

    /**
     *
     * @param argPathFiltersMap
     */
    public void setPathFilters(final Map<String, String> argPathFiltersMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathFilters(%s) ", argPathFiltersMap);
      if (handler != null) {
        KcRoutingHandler.setPathFilters(argPathFiltersMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathFilters(null)");
      }
    }

    /**
     *
     * @param argPathBlocksMap
     */
    public void setPathBlocks(final Map<String, String> argPathBlocksMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathBlocks(%s) ", argPathBlocksMap);
      if (handler != null) {
        KcRoutingHandler.setPathBlocks(argPathBlocksMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathBlocks(null)");
      }
    }

    /**
     *
     * @param argPathRecursiveBlocksMap
     */
    public void setPathRecursiveBlocks(final Map<String, String> argPathRecursiveBlocksMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathRecursiveBlocks(%s) ", argPathRecursiveBlocksMap);
      if (handler != null) {
        KcRoutingHandler.setPathRecursiveBlocks(argPathRecursiveBlocksMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathRecursiveBlocks(null)");
      }
    }

    /**
     *
     * @param argPathAllowsMap
     */
    public void setPathAllows(final Map<String, String> argPathAllowsMap) {
      LOGGER.debugf("KcRoutingRecorder::setPathAllows(%s) ", argPathAllowsMap);
      if (handler != null) {
        KcRoutingHandler.setPathAllows(argPathAllowsMap);
      } else {
        LOGGER.debug("KcRoutingRecorder::setPathAllows(null)");
      }
    }
}
