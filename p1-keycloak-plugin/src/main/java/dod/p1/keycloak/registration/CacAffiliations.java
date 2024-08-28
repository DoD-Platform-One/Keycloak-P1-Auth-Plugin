package dod.p1.keycloak.registration;

import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class creation results solely from Fortify scans balking on reading properties in from
 * the resources directory.  It provides a utility for translating DoD CAC affiliation values(short names) to
 * front end affiliation values(long names) and visa-versa.
 */
final class CacAffiliations {
    /**
     * This collection object will store the CAC Affiliations with the keys set to the short name.
     * The values will be the affiliation long name.
     */
    private static final Properties SHORT_NAME_TRANSLATOR;

    /**
     * This collection object will store the CAC Affiliations with the keys set to the long name.
     * The values will be the affiliation short name.
     */
    private static final Properties LONG_NAME_TRANSLATOR;

    /**
     * The logger.
     */
    private static final Logger LOGGER;

    static {
        LOGGER = LogManager.getLogger(CacAffiliations.class);
        SHORT_NAME_TRANSLATOR = createShortNameTranslator();
        LONG_NAME_TRANSLATOR = createLongNameTranslator();
    }

    /**
     * Making constructor private so that instantiation cannot occur.
     */
    private CacAffiliations() {
    }

    /**
     * Creates  a Properties object used for translating DoD CAC Affiliation values between long and short names.
     * @return Properties
     */
    private static Properties createShortNameTranslator() {
        Properties collection = new Properties();
        collection.put("USAF", "US Air Force");
        collection.put("USAFR", "US Air Force Reserve");
        collection.put("USANG", "US Air National Guard");
        collection.put("USARMY", "US Army");
        collection.put("USARMYR", "US Army Reserve");
        collection.put("USARMYNG", "US Army National Guard");
        collection.put("USCG", "US Coast Guard");
        collection.put("USCGR", "US Coast Guard Reserve");
        collection.put("USMC", "US Marine Corps");
        collection.put("USMCR", "US Marine Corps Reserve");
        collection.put("USNAVY", "US Navy");
        collection.put("USNAVYR", "US Navy Reserve");
        collection.put("USSF", "US Space Force");
        collection.put("DoD", "Dept of Defense");
        collection.put("U.S. Government", "Federal Government");
        collection.put("AAS", "A&AS");
        collection.put("CONTRACTOR", "Contractor");
        collection.put("FFRDC", "FFRDC");
        collection.put("OTHER", "Other");
        LOGGER.debug("Created short name translator.");
        return collection;
    }

    /**
     * Creates a Properties object for translating CAC affiliation long names to short names.
     * @return Properties object
     */
    private static Properties createLongNameTranslator() {
        Properties retVal = new Properties();
        SHORT_NAME_TRANSLATOR.forEach((x, y) -> retVal.put(y, x));
        LOGGER.debug("Created long name translator.");
        return retVal;
    }

    /**
     * This method translates the CAC affiliation short name into the long name.
     * @param shortName the shortened version of the CAC affiliation which is stored on a CAC.
     * @return String - the CAC Affiliation long name for the provided shortname and null if key does not exist.
     */
    public static String getLongName(final String shortName) {
        if (!SHORT_NAME_TRANSLATOR.containsKey(shortName)) {
            LOGGER.warn("Affiliation short name not found, returning null for long name");
        }
        return SHORT_NAME_TRANSLATOR.getProperty(shortName);
    }

    /**
     * This method translates the CAC affiliation long name into the short name.
     * @param longName the long version of the CAC affiliation which is visible on the front end.
     * @return String - the CAC Affiliation short name for the provided long name and null if key does not exist.
     */
    public static String getShortName(final String longName) {
        if (!LONG_NAME_TRANSLATOR.containsKey(longName)) {
            LOGGER.warn("Affiliation long name not found, returning null for short name");
        }
        return LONG_NAME_TRANSLATOR.getProperty(longName);
    }
}
