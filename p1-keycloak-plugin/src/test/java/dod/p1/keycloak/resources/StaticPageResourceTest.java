package dod.p1.keycloak.resources;

import dod.p1.keycloak.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.mockito.ArgumentCaptor;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link StaticPageResource}.
 */
class StaticPageResourceTest {

    private StaticPageResource subjectUnderTest;
    private KeycloakSession mockSession;
    private LoginFormsProvider mockFormsProvider;
    private Response mockResponse;

    @BeforeEach
    void setup() throws Exception {
        Utils.setupFileMocks();
        
        mockSession = mock(KeycloakSession.class);
        mockFormsProvider = mock(LoginFormsProvider.class);
        mockResponse = mock(Response.class);
        
        when(mockSession.getProvider(LoginFormsProvider.class)).thenReturn(mockFormsProvider);
        when(mockFormsProvider.setAttribute(anyString(), any())).thenReturn(mockFormsProvider);
        when(mockFormsProvider.createForm(anyString())).thenReturn(mockResponse);
        
        subjectUnderTest = new StaticPageResource(mockSession);
    }

    @Test
    void testGetResource() {
        // The getResource method should return the resource itself
        Object result = subjectUnderTest.getResource();
        assertSame(subjectUnderTest, result);
    }

    @Test
    void testClose() {
        // The close method doesn't do anything substantive, but we should test it for coverage
        subjectUnderTest.close();
        // No assertions needed, just verify it doesn't throw exceptions
    }

    @Test
    void testGetPage_ApprovedPage() {
        // Test with an approved page
        Response result = subjectUnderTest.getPage("faq");
        
        // Verify the correct template was requested
        verify(mockFormsProvider).createForm("faq.ftl");
        
        // Verify the staticPage attribute was set
        verify(mockFormsProvider).setAttribute("staticPage", Boolean.TRUE);
        
        // Verify the response from the forms provider is returned
        assertSame(mockResponse, result);
    }

    @Test
    void testGetPage_NonApprovedPage() {
        // Test with a non-approved page
        Response result = subjectUnderTest.getPage("unauthorized-page");
        
        // Verify the error template was requested
        verify(mockFormsProvider).createForm("error.ftl");
        
        // Verify the staticPage attribute was set
        verify(mockFormsProvider).setAttribute("staticPage", Boolean.TRUE);
        
        // Verify the response from the forms provider is returned
        assertSame(mockResponse, result);
    }

    @Test
    void testGetPage_TemplateException() {
        // Setup the forms provider to throw an exception when createForm is called
        when(mockFormsProvider.createForm("faq.ftl")).thenThrow(new RuntimeException("Template error"));
        
        // Test with an approved page that will cause an exception
        Response result = subjectUnderTest.getPage("faq");
        
        // Verify the error template was requested as fallback
        verify(mockFormsProvider).createForm("error.ftl");
        
        // Verify the response from the forms provider is returned
        assertSame(mockResponse, result);
    }

    @Test
    void testGetPage_FallbackErrorException() {
        // Setup the forms provider to throw exceptions for both the main template and the error template
        when(mockFormsProvider.createForm("faq.ftl")).thenThrow(new RuntimeException("Template error"));
        when(mockFormsProvider.createForm("error.ftl")).thenThrow(new RuntimeException("Error template error"));
        
        // Mock the Response.ResponseBuilder for the fallback error response
        Response.ResponseBuilder mockBuilder = mock(Response.ResponseBuilder.class);
        Response mockErrorResponse = mock(Response.class);
        
        // Setup the static mock for Response.status
        try (var responseMock = mockStatic(Response.class)) {
            responseMock.when(() -> Response.status(eq(Response.Status.INTERNAL_SERVER_ERROR)))
                    .thenReturn(mockBuilder);
            
            when(mockBuilder.header(eq("Content-Type"), anyString())).thenReturn(mockBuilder);
            when(mockBuilder.type(MediaType.TEXT_HTML)).thenReturn(mockBuilder);
            when(mockBuilder.entity(anyString())).thenReturn(mockBuilder);
            when(mockBuilder.build()).thenReturn(mockErrorResponse);
            
            // Test with an approved page that will cause exceptions
            Response result = subjectUnderTest.getPage("faq");
            
            // Verify the correct status was used
            responseMock.verify(() -> Response.status(Response.Status.INTERNAL_SERVER_ERROR));
            
            // Verify the content type was set
            verify(mockBuilder).header("Content-Type", MediaType.TEXT_HTML + ";charset=UTF-8");
            
            // Verify the media type was set
            verify(mockBuilder).type(MediaType.TEXT_HTML);
            
            // Verify some error content was included
            ArgumentCaptor<String> contentCaptor = ArgumentCaptor.forClass(String.class);
            verify(mockBuilder).entity(contentCaptor.capture());
            String content = contentCaptor.getValue();
            assert(content.contains("<html>") && content.contains("Error"));
            
            // Verify the fallback error response is returned
            assertSame(mockErrorResponse, result);
        }
    }
}