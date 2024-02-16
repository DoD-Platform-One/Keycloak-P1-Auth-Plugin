package org.keycloak.forms.account.freemarker.model;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.forms.account.freemarker.model.UrlBean;
import org.keycloak.models.RealmModel;
import org.keycloak.services.AccountUrls;
import org.keycloak.theme.Theme;
import org.keycloak.theme.Theme.Type;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.junit.runner.RunWith;
import org.keycloak.services.Urls;

import java.io.IOException;
import java.net.URI;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({AccountUrls.class, Urls.class})
public class UrlBeanTest {

    private RealmModel realmModel;
    private Theme theme;
    private URI baseUri;
    private URI baseQueryUri;
    private URI currentUri;

    @Before
    public void setUp() throws IOException{
        // Mock dependencies
        realmModel = mock(RealmModel.class);
        theme = mock(Theme.class);
        baseUri = URI.create("http://example.com/base");
        baseQueryUri = URI.create("http://example.com/base/query");
        currentUri = URI.create("http://example.com/current");

        // Stub necessary methods
        when(realmModel.getName()).thenReturn("testRealm");
        when(theme.getType()).thenReturn(Type.WELCOME);
        when(theme.getName()).thenReturn("testTheme");

        // Mock static method calls
        URI defaultURI = URI.create("http://example.com/default");

        mockStatic(AccountUrls.class, Urls.class);
        when(AccountUrls.accountApplicationsPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountPasswordPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountFederatedIdentityPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountTotpPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountLogPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountSessionsPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountLogout(any(URI.class), any(URI.class), any(String.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountResourcesPage(any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountResourceDetailPage(any(String.class), any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountResourceGrant(any(String.class), any(URI.class), any(String.class))).thenReturn(defaultURI);
        when(AccountUrls.accountResourceShare(any(String.class), any(URI.class), any(String.class))).thenReturn(defaultURI);

        Properties properties = mock(Properties.class);
        when(theme.getProperties()).thenReturn(properties);
        when(AccountUrls.themeRoot(any(URI.class))).thenReturn(defaultURI);
    }

    @Test
    public void testUrlBeanMethods() {
        // Create an instance of UrlBean
        UrlBean urlBean = new UrlBean(realmModel, theme, baseUri, baseQueryUri, currentUri, "idTokenHint");

        // Test various URL construction methods
        urlBean.getApplicationsUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountApplicationsPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getAccountUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getPasswordUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountPasswordPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getSocialUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountFederatedIdentityPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getTotpUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountTotpPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getLogUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountLogPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getSessionsUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountSessionsPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getLogoutUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountLogout(eq(baseQueryUri), eq(currentUri), eq("testRealm"), eq("idTokenHint"));

        urlBean.getResourceUrl();
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountResourcesPage(eq(baseQueryUri), eq("testRealm"));

        urlBean.getResourceDetailUrl("resourceId");
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountResourceDetailPage(eq("resourceId"), eq(baseQueryUri), eq("testRealm"));

        urlBean.getResourceGrant("resourceId");
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountResourceGrant(eq("resourceId"), eq(baseQueryUri), eq("testRealm"));

        urlBean.getResourceShare("resourceId");
        verifyStatic(AccountUrls.class, times(1));
        AccountUrls.accountResourceShare(eq("resourceId"), eq(baseQueryUri), eq("testRealm"));

        urlBean.getResourcesPath();
        AccountUrls.themeRoot(eq(baseUri));

        urlBean.getResourcesCommonPath();
        AccountUrls.themeRoot(eq(baseUri));
    }
}
