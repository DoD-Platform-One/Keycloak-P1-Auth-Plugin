package org.keycloak.services;

import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.OAuth2Constants;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.resources.account.AccountFormService;

/**
 * Utility class for constructing URLs related to the account pages and actions.
 */
@JBossLog
public class AccountUrls extends Urls {

  /**
   * Constructs the URI builder for realm logout.
   *
   * @param baseUri The base URI.
   * @return The URI builder for realm logout.
   */
  private static UriBuilder realmLogout(final URI baseUri) {
    return tokenBase(baseUri).path(OIDCLoginProtocolService.class, "logout");
  }

  /**
   * Gets the base URI for account-related operations.
   *
   * @param baseUri The base URI.
   * @return The UriBuilder for account-related operations.
   */
  public static UriBuilder accountBase(final URI baseUri) {
    return realmBase(baseUri).path(RealmsResource.class, "getAccountService");
  }

  /**
   * Constructs the URI builder for the token base.
   *
   * @param baseUri The base URI.
   * @return The URI builder for the token base.
   */
  private static UriBuilder tokenBase(final URI baseUri) {
    return realmBase(baseUri).path("{realm}/protocol/" + OIDCLoginProtocol.LOGIN_PROTOCOL);
  }

  /**
   * Constructs the URI for the account applications page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account applications page.
   */
  public static URI accountApplicationsPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "applicationsPage").build(realmName);
  }

  /**
   * Constructs the URI for the account applications page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account applications page.
   */
  public static URI accountPage(final URI baseUri, final String realmName) {
    return accountPageBuilder(baseUri).build(realmName);
  }

  /**
   * Constructs the URI builder for the account page.
   *
   * @param baseUri The base URI.
   * @return The URI builder for the account page.
   */
  public static UriBuilder accountPageBuilder(final URI baseUri) {
    return accountBase(baseUri).path(AccountFormService.class, "accountPage");
  }

  /**
   * Constructs the URI for the account password page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account password page.
   */
  public static URI accountPasswordPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "passwordPage").build(realmName);
  }

  /**
   * Constructs the URI for the account federated identity page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account federated identity page.
   */
  public static URI accountFederatedIdentityPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri)
        .path(AccountFormService.class, "federatedIdentityPage")
        .build(realmName);
  }

  /**
   * Constructs the URI for processing federated identity update.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for processing federated identity update.
   */
  public static URI accountFederatedIdentityUpdate(final URI baseUri, final String realmName) {
    return accountBase(baseUri)
        .path(AccountFormService.class, "processFederatedIdentityUpdate")
        .build(realmName);
  }

  /**
   * Constructs the URI for the account TOTP page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account TOTP page.
   */
  public static URI accountTotpPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "totpPage").build(realmName);
  }

  /**
   * Constructs the URI for the account log page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account log page.
   */
  public static URI accountLogPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "logPage").build(realmName);
  }

  /**
   * Constructs the URI for the account sessions page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account sessions page.
   */
  public static URI accountSessionsPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "sessionsPage").build(realmName);
  }

  /**
   * Constructs the URI for the account logout.
   *
   * @param baseUri      The base URI.
   * @param redirectUri  The URI to redirect after logout.
   * @param realmName    The realm name.
   * @param idTokenHint  The ID token hint.
   * @return The constructed URI for the account logout.
   */
  public static URI accountLogout(
      final URI baseUri, final URI redirectUri, final String realmName, final String idTokenHint) {
    return realmLogout(baseUri)
        .queryParam(OAuth2Constants.POST_LOGOUT_REDIRECT_URI, redirectUri)
        .queryParam(OAuth2Constants.ID_TOKEN_HINT, idTokenHint)
        .build(realmName);
  }

  /**
   * Constructs the URI for the account resources page.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the account resources page.
   */
  public static URI accountResourcesPage(final URI baseUri, final String realmName) {
    return accountBase(baseUri).path(AccountFormService.class, "resourcesPage").build(realmName);
  }

  /**
   * Constructs the URI for the account resource detail page.
   *
   * @param resourceId The resource ID.
   * @param baseUri    The base URI.
   * @param realmName  The realm name.
   * @return The constructed URI for the account resource detail page.
   */
  public static URI accountResourceDetailPage(final String resourceId, final URI baseUri, final String realmName) {
    return accountBase(baseUri)
        .path(AccountFormService.class, "resourceDetailPage")
        .build(realmName, resourceId);
  }

  /**
   * Constructs the URI for granting permission to a resource.
   *
   * @param resourceId The resource ID.
   * @param baseUri    The base URI.
   * @param realmName  The realm name.
   * @return The constructed URI for granting permission to a resource.
   */

  public static URI accountResourceGrant(final String resourceId, final URI baseUri, final String realmName) {
    return accountBase(baseUri)
        .path(AccountFormService.class, "grantPermission")
        .build(realmName, resourceId);
  }

  /**
   * Constructs the URI for sharing a resource.
   *
   * @param resourceId The resource ID.
   * @param baseUri    The base URI.
   * @param realmName  The realm name.
   * @return The constructed URI for sharing a resource.
   */
  public static URI accountResourceShare(final String resourceId, final URI baseUri, final String realmName) {
    return accountBase(baseUri)
        .path(AccountFormService.class, "shareResource")
        .build(realmName, resourceId);
  }

  /**
   * Constructs the URI for the login action to update the password.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the login action to update the password.
   */
  public static URI loginActionUpdatePassword(final URI baseUri, final String realmName) {
    return loginActionsBase(baseUri)
        .path(LoginActionsService.class, "updatePassword")
        .build(realmName);
  }

  /**
   * Constructs the URI for the login action to update the TOTP.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The constructed URI for the login action to update the TOTP.
   */
  public static URI loginActionUpdateTotp(final URI baseUri, final String realmName) {
    return loginActionsBase(baseUri).path(LoginActionsService.class, "updateTotp").build(realmName);
  }

  /**
   * Gets the path for the locale cookie based on the realm name.
   *
   * @param baseUri   The base URI.
   * @param realmName The realm name.
   * @return The path for the locale cookie.
   */
  public static String localeCookiePath(final URI baseUri, final String realmName) {
    return realmBase(baseUri).path(realmName).build().getRawPath();
  }
}
