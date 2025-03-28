package dod.p1.keycloak.registration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CacAffiliationsTest {

    private final Properties controlObjectShortNameTranslator = new Properties();
    private final Properties controlObjectLongNameTranslator = new Properties();

    @BeforeEach
    public void setUp() {
        // Short name translator translates affiliation short name to affiliation long name
        controlObjectShortNameTranslator.put("USAF", "US Air Force");
        controlObjectShortNameTranslator.put("USAFR", "US Air Force Reserve");
        controlObjectShortNameTranslator.put("USANG", "US Air National Guard");
        controlObjectShortNameTranslator.put("USARMY", "US Army");
        controlObjectShortNameTranslator.put("USARMYR", "US Army Reserve");
        controlObjectShortNameTranslator.put("USARMYNG", "US Army National Guard");
        controlObjectShortNameTranslator.put("USCG", "US Coast Guard");
        controlObjectShortNameTranslator.put("USCGR", "US Coast Guard Reserve");
        controlObjectShortNameTranslator.put("USMC", "US Marine Corps");
        controlObjectShortNameTranslator.put("USMCR", "US Marine Corps Reserve");
        controlObjectShortNameTranslator.put("USNAVY", "US Navy");
        controlObjectShortNameTranslator.put("USNAVYR", "US Navy Reserve");
        controlObjectShortNameTranslator.put("USSF", "US Space Force");
        controlObjectShortNameTranslator.put("DoD", "Dept of Defense");
        controlObjectShortNameTranslator.put("U.S. Government", "Federal Government");
        controlObjectShortNameTranslator.put("OTHER", "Other");
        controlObjectShortNameTranslator.put("AAS", "A&AS");
        controlObjectShortNameTranslator.put("CONTRACTOR", "Contractor");
        controlObjectShortNameTranslator.put("FFRDC", "FFRDC");
        // Duplicate "OTHER" key intentionally overwritten
        controlObjectShortNameTranslator.put("OTHER", "Other");

        // Build the long name translator by swapping keys and values
        controlObjectShortNameTranslator.forEach((shortName, longName) ->
            controlObjectLongNameTranslator.put(longName.toString(), shortName.toString())
        );
    }

    @Test
    public void getLongName() {
        // Verify that for each short name, the CacAffiliations.getLongName matches our control object
        controlObjectShortNameTranslator.forEach((shortName, longName) ->
            assertEquals(longName.toString(), CacAffiliations.getLongName(shortName.toString()))
        );
    }

    @Test
    public void getShortName() {
        // Verify that for each long name, the CacAffiliations.getShortName matches our control object
        controlObjectLongNameTranslator.forEach((longName, shortName) ->
            assertEquals(shortName.toString(), CacAffiliations.getShortName(longName.toString()))
        );
    }
}
