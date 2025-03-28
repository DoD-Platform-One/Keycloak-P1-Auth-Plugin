package dod.p1.keycloak.utils;

import dod.p1.keycloak.common.YAMLConfig;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 * The sole purpose of this class is to allow for unit test coverage.
 * The Jacoco test coverage report is not fully compatible with the PowerMock testing framework.
 * This class is used in @PrepareForTest so that the Jacoco report detects test coverage for CommonConfig class.
 */
public final class NewObjectProvider {

    private NewObjectProvider() {
        // hide public constructor. No need to ever declare an instance. All methods are static.
    }

    /**
     * Get new java.io.File object.
     * @param filePath a String
     * @return File
     */
    public static File getFile(final String filePath) {
        return new File(filePath);
    }

    /**
     * Get new java.io.InputStream object.
     * @param file a File object
     * @return InputStream
     * @throws FileNotFoundException if the file is not found
     */
    public static InputStream getFileInputStream(final File file) throws FileNotFoundException {
        return new FileInputStream(file);
    }

    /**
     * Get new org.yaml.snakeyaml.Yaml object.
     * @return Yaml
     */
    public static Yaml getYaml() {
        return new Yaml(new Constructor(YAMLConfig.class, new LoaderOptions()));
    }
}
