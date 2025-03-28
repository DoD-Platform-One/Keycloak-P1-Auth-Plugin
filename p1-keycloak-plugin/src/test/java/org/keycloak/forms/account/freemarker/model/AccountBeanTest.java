package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccountBeanTest {

    @Test
    void testAccountBean() {
        // Mock UserModel
        UserModel mockUserModel = mock(UserModel.class);
        when(mockUserModel.getUsername()).thenReturn("UserUsername");
        when(mockUserModel.getFirstName()).thenReturn("UserFirstName");
        when(mockUserModel.getLastName()).thenReturn("UserLastName");
        when(mockUserModel.getEmail()).thenReturn("user@example.com");
        when(mockUserModel.getAttributes()).thenReturn(createMockAttributes());

        // Test case 1: Basic scenario
        MultivaluedMap<String, String> profileFormData1 = new MultivaluedHashMap<>();
        profileFormData1.add("firstName", "John");
        profileFormData1.add("lastName", "Doe");
        profileFormData1.add("username", "johndoe");
        profileFormData1.add("email", "john.doe@example.com");
        profileFormData1.addAll("customAttribute1", List.of("value1"));
        profileFormData1.addAll("customAttribute2", List.of("value2"));

        AccountBean accountBean1 = new AccountBean(mockUserModel, profileFormData1);

        assertEquals("John", accountBean1.getFirstName());
        assertEquals("Doe", accountBean1.getLastName());
        assertEquals("johndoe", accountBean1.getUsername());
        assertEquals("john.doe@example.com", accountBean1.getEmail());
        assertEquals("value1", accountBean1.getAttributes().get("customAttribute1"));
        assertEquals("value2", accountBean1.getAttributes().get("customAttribute2"));
        assertEquals("default1", accountBean1.getAttributes().get("customDefaultAttribute1"));
        assertEquals("default2", accountBean1.getAttributes().get("customDefaultAttribute2"));

        // Test case 2: ProfileFormData is null
        AccountBean accountBean2 = new AccountBean(mockUserModel, null);

        assertEquals("UserFirstName", accountBean2.getFirstName());
        assertEquals("UserLastName", accountBean2.getLastName());
        assertEquals("UserUsername", accountBean2.getUsername());
        assertEquals("user@example.com", accountBean2.getEmail());
        assertNull(accountBean2.getAttributes().get("customAttribute1"));
        assertNull(accountBean2.getAttributes().get("customAttribute2"));
        assertEquals("default1", accountBean2.getAttributes().get("customDefaultAttribute1"));
        assertEquals("default2", accountBean2.getAttributes().get("customDefaultAttribute2"));
    }

    private Map<String, List<String>> createMockAttributes() {
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("customDefaultAttribute1", List.of("default1"));
        attributes.put("customDefaultAttribute2", List.of("default2"));
        return attributes;
    }
}
