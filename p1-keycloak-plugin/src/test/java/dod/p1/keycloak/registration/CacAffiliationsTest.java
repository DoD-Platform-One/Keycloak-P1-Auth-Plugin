package dod.p1.keycloak.registration;

import org.junit.Before;
import org.junit.Test;

import java.util.Properties;

import static org.junit.Assert.*;

public class CacAffiliationsTest {
    private final Properties controlObjectShortNameTranslator = new Properties();
    private final Properties controlObjectLongNameTranslator = new Properties();

    @Before
    public void setUp() throws Exception {
        /** short name translator translates affiliation short name to affiliation long name **/
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
        controlObjectShortNameTranslator.put("OTHER", "Other");
        /** long name translator translates affiliation long name to affiliation short name and is built
         * from short name translator switching keys to values and values to keys
         */

        controlObjectShortNameTranslator.forEach((x, y) -> controlObjectLongNameTranslator.put(y.toString(), x.toString()));
    }

    @Test
    public void getLongName() {
        controlObjectShortNameTranslator.forEach((x,y) -> assertEquals(y.toString(), CacAffiliations.getLongName(x.toString())));
    }

    @Test
    public void getShortName() {
        controlObjectLongNameTranslator.forEach((x,y) -> assertEquals(y.toString(), CacAffiliations.getShortName(x.toString())));
    }
}