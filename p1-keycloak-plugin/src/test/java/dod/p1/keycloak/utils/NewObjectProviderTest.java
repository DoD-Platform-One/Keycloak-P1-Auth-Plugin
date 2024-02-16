package dod.p1.keycloak.utils;


import dod.p1.keycloak.common.YAMLConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({File.class, FileInputStream.class, Yaml.class})
public class NewObjectProviderTest {

    @Mock
    private File fileMock;

    @Test
    public void testGetFile() throws Exception {
        // Mocking
        whenNew(File.class).withArguments("testPath").thenReturn(fileMock);

        // Testing
        File file = NewObjectProvider.getFile("testPath");

        // Verifying
        assertEquals("testPath", file.getPath());
    }

    @Test
    public void testGetFileInputStream() throws Exception {
        // File
        File file = new File("./lombok.config");

        // Testing
        FileInputStream fileInputStream = NewObjectProvider.getFileInputStream(file);

        // Verifying
        assertNotNull(fileInputStream);
    }

    @Test
    public void testGetYaml() throws Exception {
        // Mock the Yaml constructor using PowerMockito
        Yaml mockYaml = mock(Yaml.class);
        whenNew(Yaml.class).withArguments(new Constructor(YAMLConfig.class)).thenReturn(mockYaml);

        // Invoke the method under test
        Yaml result = NewObjectProvider.getYaml();

        // Verify that the mocked Yaml is returned
        assertNotNull(result);
    }
}
