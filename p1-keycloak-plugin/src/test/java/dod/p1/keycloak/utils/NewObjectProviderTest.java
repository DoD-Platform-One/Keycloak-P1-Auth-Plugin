package dod.p1.keycloak.utils;

import dod.p1.keycloak.common.YAMLConfig;
import org.yaml.snakeyaml.Yaml;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NewObjectProviderTest {

    @BeforeAll
    static void init() throws ClassNotFoundException {
        // Force load the NewObjectProvider class so it’s initialized.
        Class.forName("dod.p1.keycloak.utils.NewObjectProvider");
    }

    @Test
    void testLoadClassDirectly() throws Exception {
        Class<?> clazz = Class.forName("dod.p1.keycloak.utils.NewObjectProvider");
        assertNotNull(clazz, "NewObjectProvider class should be loaded");
    }

    @Test
    void testGetFile() {
        // Use Mockito's mockConstruction to intercept File construction.
        try (var mockedFileConstruction =
                org.mockito.Mockito.mockConstruction(File.class, (mock, context) -> {
                    when(mock.getPath()).thenReturn("testPath");
                })) {
            File file = NewObjectProvider.getFile("testPath");
            assertNotNull(file, "The File object should not be null");
            // Verify that the constructed File has the expected path.
            File constructedFile = mockedFileConstruction.constructed().get(0);
            assertEquals("testPath", constructedFile.getPath(), "File path should match the argument passed");
        }
    }

    @Test
    void testGetFileInputStream_Success() throws Exception {
        // Create a temporary file to avoid FileNotFoundException.
        File tempFile = File.createTempFile("temp", ".txt");
        tempFile.deleteOnExit();

        try (var fileInputStreamConstruction =
                org.mockito.Mockito.mockConstruction(FileInputStream.class)) {
            InputStream fis = NewObjectProvider.getFileInputStream(tempFile);
            assertNotNull(fis, "FileInputStream should not be null");
            // Verify that one FileInputStream instance was constructed.
            assertEquals(1, fileInputStreamConstruction.constructed().size(), "Expected one FileInputStream construction");
        }
    }

    @Test
    void testGetFileInputStream_FileNotFound() {
        // Create a File object that does not exist.
        File nonExistentFile = new File("this_file_does_not_exist.txt");
        // Expect FileNotFoundException to be thrown.
        assertThrows(FileNotFoundException.class, () -> {
            NewObjectProvider.getFileInputStream(nonExistentFile);
        }, "Expected FileNotFoundException for non-existent file");
    }

    @Test
    void testGetYaml_Construction() {
        try (var yamlConstruction =
                org.mockito.Mockito.mockConstruction(Yaml.class)) {
            Yaml result = NewObjectProvider.getYaml();
            assertNotNull(result, "Yaml result should not be null");
            assertEquals(1, yamlConstruction.constructed().size(), "Expected exactly one Yaml construction");
        }
    }

    @Test
    void testGetYaml_ParsesYAMLConfig() {
        // Use an empty YAML mapping which is valid for YAMLConfig.
        String yamlStr = "{}";
        Yaml yaml = NewObjectProvider.getYaml();
        YAMLConfig config = yaml.loadAs(yamlStr, YAMLConfig.class);
        assertNotNull(config, "YAMLConfig instance should not be null");
        // Additional assertions can be added if YAMLConfig has default values or getters.
    }
}
