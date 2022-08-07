package dod.p1.keycloak.utils;

import dod.p1.keycloak.common.YAMLConfig;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

/**
 * The sole purpose of this class is to allow for unit test coverage
 * The Jaccoco test coverage report is not fully compatible with the PowerMock testing framework
 * This class is used in @PrepareForTest so that the Jaccoco report detects test coverage for CommonConfig class.
 */
public class NewObjectProvider {

    /**
     * Get new java.io.File object
     * @param filePath a String
     * @return File
     */
    public static File getFile(String filePath){
        return new File(filePath);
    }

    /**
     * Get new java.io.FileInputStream object
     * @param file a File object
     * @return FileInputStream
     */
    public static FileInputStream getFileInputStream(File file) throws FileNotFoundException {
        return new FileInputStream(file);
    }

    /**
     * Get new org.yaml.snakeyaml.Yaml object
     * @return Yaml
     */
    public static Yaml getYaml(){
      return new Yaml(new Constructor(YAMLConfig.class));
    }

}
