/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.services.resources.account;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.extern.jbosslog.JBossLog;
import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.Event;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.forms.account.AccountPages;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.locale.LocaleUpdaterProvider;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelException;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.IDToken;
import org.keycloak.services.AccountUrls;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserConsentManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resource.AccountResourceProvider;
import org.keycloak.services.resources.AbstractSecuredLocalService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.userprofile.EventAuditingAttributeChangeListener;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.CredentialHelper;

/**
 * The {@code AccountFormService} class implements the {@code AccountResourceProvider} interface and extends
 * {@code AbstractSecuredLocalService}. It provides functionality related to account management and serves
 * as a resource provider for account-related operations.
 *
 * The class includes a static logger named {@code LOGGER} for logging purposes and maintains a set of valid paths
 * based on methods annotated with {@code @Path}. The valid paths are stored in the {@code validPaths} set.
 *
 * This class is designed to handle resource provisioning for account management and is likely part of a larger
 * system responsible for user account interactions.
 *
 * Note: The class utilizes the JBoss Logging framework with the {@code @JBossLog} annotation for logging.
 *
 * @see AbstractSecuredLocalService
 * @see AccountResourceProvider
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@JBossLog
public class AccountFormService extends AbstractSecuredLocalService
    implements AccountResourceProvider {

  /**
   * Returns the instance of this class as a resource.
   *
   * @return The instance of this class.
   */
  @Override
  public Object getResource() {
    return this;
  }

  /**
   * Closes any resources associated with this class. This method is empty, indicating no specific cleanup
   * or resource release.
   */
  @Override
  public void close() {
    // Closes any resources associated with this class. This method is empty, indicating no specific cleanup
    // or resource release.
  }

  /** The logger for this class. */
  private static final Logger LOGGER = Logger.getLogger(AccountFormService.class);

  /** Set of valid paths based on methods annotated with @Path. */
  private static Set<String> validPaths = new HashSet<>();

  static {
    for (Method m : AccountFormService.class.getMethods()) {
      Path p = m.getAnnotation(Path.class);
      if (p != null) {
        validPaths.add(p.value());
      }
    }
  }

  // Used when some other context (ie. IdentityBrokerService) wants to forward error to account
  // management and display it here
  /** Constant representing the note key for forwarded errors in account management. */
  public static final String ACCOUNT_MGMT_FORWARDED_ERROR_NOTE = "ACCOUNT_MGMT_FORWARDED_ERROR";

  /** Manager responsible for handling authentication operations in the application. */
  private final AppAuthManager authManager;

  /** Builder for creating events and logging within the account management service. */
  private final EventBuilder event;

  /** Provider for accessing account-related functionalities. */
  private AccountProvider account;

  /** Provider for accessing event store functionalities. */
  private EventStoreProvider eventStore;

  /** A constant representing the maximum number of results for events. */
  private static final int MAX_EVENT_RESULTS = 30;

  // Sonarqube consider this a critical issue
  /** PSSWD constant. */
  private static final String PSSWD = "password";

  /** REFERRER constant. */
  private static final String REFERRER = "referrer";

  /** RESOURCE constant. */
  private static final String RESOURCE = "resource";

  /** INVALID_RESOURCE constant. */
  private static final String INVALID_RESOURCE = "Invalid resource";

  /**
   * Constructs an instance of {@code AccountFormService} with the provided Keycloak session,
   * client model, and event builder. This class is responsible for managing account-related
   * operations and interactions.
   *
   * @param session The Keycloak session associated with the service.
   * @param client The client model representing the client application.
   * @param eventBuilder The builder for creating events and logging.
   */
  public AccountFormService(final KeycloakSession session, final ClientModel client, final EventBuilder eventBuilder) {
    super(session, client);
    this.event = eventBuilder;
    this.authManager = new AppAuthManager();
    init();
  }

  /**
   * Initializes the AccountFormService by setting up necessary providers, authenticating
   * the user, validating the request origin and referer, and configuring various features.
   */
  public void init() {
    log.info("init");
    session.getContext().setClient(client);
    eventStore = session.getProvider(EventStoreProvider.class);
    setupAccountProvider();

    AuthenticationManager.AuthResult authResult =
        authManager.authenticateIdentityCookie(session, realm);
    if (authResult != null) {
      setupAuthentication(authResult);
    }

    validateRequestOrigin();

    if (authResult != null) {
      setupUserSession(authResult);
    }

    configureFeatures();
  }

  /**
   * Sets up the account provider with realm and URI information.
   */
  private void setupAccountProvider() {
    account =
        session
            .getProvider(AccountProvider.class)
            .setRealm(realm)
            .setUriInfo(session.getContext().getUri());

    // In test environments, headers might be null during initialization
    if (headers != null) {
        account.setHttpHeaders(headers);
    }
  }

  /**
   * Sets up authentication based on the authentication result.
   *
   * @param authResult The authentication result
   */
  private void setupAuthentication(final AuthenticationManager.AuthResult authResult) {
    stateChecker = (String) session.getAttribute("state_checker");
    auth =
        new Auth(
            realm,
            authResult.getToken(),
            authResult.getUser(),
            client,
            authResult.getSession(),
            true);
    account.setStateChecker(stateChecker);
  }

  /**
   * Validates the request origin and referrer to prevent cross-site attacks.
   */
  private void validateRequestOrigin() {
    String requestOrigin = UriUtils.getOrigin(session.getContext().getUri().getBaseUri());

    // In test environments, headers might be null
    if (headers != null) {
      validateOriginHeader(requestOrigin);
      validateReferrerForNonGetRequests(requestOrigin);
    }
  }

  /**
   * Validates the Origin header against the request origin.
   *
   * @param requestOrigin The origin of the request
   */
  private void validateOriginHeader(final String requestOrigin) {
    String origin = headers.getRequestHeaders().getFirst("Origin");
    if (origin != null && !origin.equals("null") && !requestOrigin.equals(origin)) {
      throw new ForbiddenException();
    }
  }

  /**
   * Validates the Referrer header for non-GET requests.
   *
   * @param requestOrigin The origin of the request
   */
  private void validateReferrerForNonGetRequests(final String requestOrigin) {
    if (!request.getHttpMethod().equals("GET")) {
      String referrer = headers.getRequestHeaders().getFirst("Referer");
      if (referrer != null && !requestOrigin.equals(UriUtils.getOrigin(referrer))) {
        throw new ForbiddenException();
      }
    }
  }

  /**
   * Sets up the user session and related components.
   *
   * @param authResult The authentication result
   */
  private void setupUserSession(final AuthenticationManager.AuthResult authResult) {
    UserSessionModel userSession = authResult.getSession();
    if (userSession != null) {
      setupClientSession(userSession);
    }

    account.setUser(auth.getUser());
    setupIdToken(authResult, userSession);
  }

  /**
   * Sets up the client session for the user session.
   *
   * @param userSession The user session model
   */
  private void setupClientSession(final UserSessionModel userSession) {
    AuthenticatedClientSessionModel clientSession =
        userSession.getAuthenticatedClientSessionByClient(client.getId());
    if (clientSession == null) {
      clientSession =
          session.sessions().createClientSession(userSession.getRealm(), client, userSession);
    }
    auth.setClientSession(clientSession);
  }

  /**
   * Sets up the ID token for the authenticated user.
   *
   * @param authResult The authentication result
   * @param userSession The user session model
   */
  private void setupIdToken(final AuthenticationManager.AuthResult authResult, final UserSessionModel userSession) {
    ClientSessionContext clientSessionCtx =
        DefaultClientSessionContext.fromClientSessionScopeParameter(
            auth.getClientSession(), session);
    IDToken idToken =
        new TokenManager()
            .responseBuilder(realm, client, event, session, userSession, clientSessionCtx)
            .accessToken(authResult.getToken())
            .generateIDToken()
            .getIdToken();
    idToken.issuedFor(client.getClientId());
    account.setIdTokenHint(session.tokens().encodeAndEncrypt(idToken));
  }

  /**
   * Configures features for the account provider.
   */
  private void configureFeatures() {
    // In test environments, Profile.getInstance() might be null
    boolean authorizationEnabled = true;
    try {
        authorizationEnabled = Profile.isFeatureEnabled(Profile.Feature.AUTHORIZATION);
    } catch (NullPointerException e) {
        // Ignore NPE in tests
    }

    account.setFeatures(
        realm.isIdentityFederationEnabled(),
        eventStore != null && realm.isEventsEnabled(),
        true,
        authorizationEnabled);
  }

  /**
   * Builds the base URL for the account service using the provided UriInfo.
   *
   * @param uriInfo The UriInfo object containing the base URI information.
   * @return A UriBuilder for the account service base URL.
   */
  public static UriBuilder accountServiceBaseUrl(final UriInfo uriInfo) {
        return uriInfo
            .getBaseUriBuilder()
            .path(RealmsResource.class)
            .path(RealmsResource.class, "getAccountService");
  }

  /**
   * Builds the URL for the applications page within the account service using the provided UriInfo.
   *
   * @param uriInfo The UriInfo object containing the base URI information.
   * @return A UriBuilder for the applications page within the account service.
   */
  public static UriBuilder accountServiceApplicationPage(final UriInfo uriInfo) {
    return accountServiceBaseUrl(uriInfo).path(AccountFormService.class, "applicationsPage");
  }

  /**
   * Retrieves the set of valid paths.
   *
   * @return A set of valid paths.
   */
  protected Set<String> getValidPaths() {
    return AccountFormService.validPaths;
  }

  /**
   * Forwards the user to the specified account page.
   *
   * @param path The path to the account page.
   * @param page The AccountPages enum representing the page.
   * @return A Response object containing the account page.
   */
  private Response forwardToPage(final String path, final AccountPages page) {
    if (auth != null) {
      Response authResponse = checkAuthentication();
      if (authResponse != null) {
        return authResponse;
      }

      setReferrerOnPage();
      UserSessionModel userSession = auth.getSession();

      processAuthenticationSession(userSession);
      updateUserLocale();

      return account.createResponse(page);
    } else {
      return login(path);
    }
  }

  /**
   * Checks if the user has the required role for account management.
   *
   * @return A Response object if authentication fails, null otherwise.
   */
  private Response checkAuthentication() {
    try {
      auth.require(AccountRoles.MANAGE_ACCOUNT);
      return null;
    } catch (ForbiddenException e) {
      return session
          .getProvider(LoginFormsProvider.class)
          .setError(Messages.NO_ACCESS)
          .createErrorPage(Response.Status.FORBIDDEN);
    }
  }

  /**
   * Processes the authentication session to handle forwarded errors.
   *
   * @param userSession The user session model.
   */
  private void processAuthenticationSession(final UserSessionModel userSession) {
    String tabId = session
        .getContext()
        .getUri()
        .getQueryParameters()
        .getFirst(org.keycloak.models.Constants.TAB_ID);

    if (tabId != null) {
      AuthenticationSessionModel authSession =
          new AuthenticationSessionManager(session)
              .getAuthenticationSessionByIdAndClient(realm, userSession.getId(), client, tabId);

      if (authSession != null) {
        processForwardedError(authSession);
      }
    }
  }

  /**
   * Processes any forwarded error from the authentication session.
   *
   * @param authSession The authentication session model.
   */
  private void processForwardedError(final AuthenticationSessionModel authSession) {
    String forwardedError = authSession.getAuthNote(ACCOUNT_MGMT_FORWARDED_ERROR_NOTE);

    if (forwardedError != null) {
      try {
        FormMessage errorMessage = JsonSerialization.readValue(forwardedError, FormMessage.class);
        account.setError(
            Response.Status.INTERNAL_SERVER_ERROR,
            errorMessage.getMessage(),
            errorMessage.getParameters());
        authSession.removeAuthNote(ACCOUNT_MGMT_FORWARDED_ERROR_NOTE);
      } catch (IOException ioe) {
        throw new IllegalArgumentException(ioe);
      }
    }
  }

  /**
   * Updates the user's locale if specified in the request.
   */
  private void updateUserLocale() {
    String locale = session
        .getContext()
        .getUri()
        .getQueryParameters()
        .getFirst(LocaleSelectorProvider.KC_LOCALE_PARAM);

    if (locale != null) {
      LocaleUpdaterProvider updater = session.getProvider(LocaleUpdaterProvider.class);
      updater.updateUsersLocale(auth.getUser(), locale);
    }
  }

  /**
   * Sets the referrer on the account page.
   */
  private void setReferrerOnPage() {
    String[] referrer = getReferrer();
    if (referrer != null) {
      account.setReferrer(referrer);
    }
  }

  /**
   * Retrieves and displays the account page.
   *
   * @return A Response object containing the account page.
   */
  @Path("/")
  @GET
  @Produces(MediaType.TEXT_HTML)
  public Response accountPage() {
    log.info("accountPage");
    return forwardToPage(null, AccountPages.ACCOUNT);
  }

  /**
   * Builds the TOTP URL using the provided base URI.
   *
   * @param base The base URI.
   * @return The UriBuilder for the TOTP page.
   */
  public static UriBuilder totpUrl(final UriBuilder base) {
    return RealmsResource.accountUrl(base).path(AccountFormService.class, "totpPage");
  }

  /**
   * Retrieves and displays the TOTP page.
   *
   * @return A Response object containing the TOTP page.
   */
  @Path("totp")
  @GET
  public Response totpPage() {
    account.setAttribute(
        "mode", session.getContext().getUri().getQueryParameters().getFirst("mode"));
    return forwardToPage("totp", AccountPages.TOTP);
  }

  /**
   * Builds the password URL using the provided base URI.
   *
   * @param base The base URI.
   * @return The UriBuilder for the password page.
   */
  public static UriBuilder passwordUrl(final UriBuilder base) {
    return RealmsResource.accountUrl(base).path(AccountFormService.class, "passwordPage");
  }

  /**
   * Retrieves and displays the password page.
   *
   * @return A Response object containing the password page.
   */
  @Path(PSSWD)
  @GET
  public Response passwordPage() {
    if (auth != null) {
      account.setPasswordSet(isPasswordSet(auth.getUser()));
    }

    return forwardToPage(PSSWD, AccountPages.PASSWORD);
  }

  /**
   * Retrieves and displays the federated identity page.
   *
   * @return A Response object containing the federated identity page.
   */
  @Path("identity")
  @GET
  public Response federatedIdentityPage() {
    return forwardToPage("identity", AccountPages.FEDERATED_IDENTITY);
  }

  /**
   * Retrieves and displays the log page.
   *
   * @return A Response object containing the log page.
   */
  @Path("log")
  @GET
  public Response logPage() {
    if (!realm.isEventsEnabled()) {
      throw new NotFoundException();
    }

    if (auth != null) {
      List<Event> events =
          eventStore
              .createQuery()
              .type(Constants.EXPOSED_LOG_EVENTS)
              .realm(auth.getRealm().getId())
              .user(auth.getUser().getId())
              .maxResults(MAX_EVENT_RESULTS)
              .getResultStream()
              .peek(
                  e -> {
                    if (e.getDetails() != null) {
                      Iterator<Map.Entry<String, String>> itr =
                          e.getDetails().entrySet().iterator();
                      while (itr.hasNext()) {
                        if (!Constants.EXPOSED_LOG_DETAILS.contains(itr.next().getKey())) {
                          itr.remove();
                        }
                      }
                    }
                  })
              .collect(Collectors.toList());
      account.setEvents(events);
    }
    return forwardToPage("log", AccountPages.LOG);
  }

  /**
   * Retrieves and displays the user sessions page.
   *
   * @return A Response object containing the user sessions page.
   */
  @Path("sessions")
  @GET
  public Response sessionsPage() {
    if (auth != null) {
      account.setSessions(
          session
              .sessions()
              .getUserSessionsStream(realm, auth.getUser())
              .collect(Collectors.toList()));
    }
    return forwardToPage("sessions", AccountPages.SESSIONS);
  }

  /**
   * Retrieves and displays the applications page.
   *
   * @return A Response object containing the applications page.
   */
  @Path("applications")
  @GET
  public Response applicationsPage() {
    return forwardToPage("applications", AccountPages.APPLICATIONS);
  }

  /**
   * Processes the update of user account information.
   *
   * @return A Response object indicating the result of processing the account update.
   */
  @Path("/")
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response processAccountUpdate() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login(null);
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);

    String action = formData.getFirst("submitAction");
    if (action != null && action.equals("Cancel")) {
      setReferrerOnPage();
      return account.createResponse(AccountPages.ACCOUNT);
    }

    csrfCheck(formData);

    UserModel user = auth.getUser();

    event
        .event(EventType.UPDATE_PROFILE)
        .client(auth.getClient())
        .user(auth.getUser())
        .detail(Details.CONTEXT, "ACCOUNT_OLD");

    UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
    UserProfile profile = profileProvider.create(UserProfileContext.ACCOUNT, formData, user);

    try {
      // backward compatibility with old account console where attributes are not removed if missing
      profile.update(false, new EventAuditingAttributeChangeListener(profile, event));
    } catch (ValidationException pve) {
      List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());

      if (!errors.isEmpty()) {
        setReferrerOnPage();
        Response.Status status = Status.OK;

        if (pve.hasError(Messages.READ_ONLY_USERNAME)) {
          status = Response.Status.BAD_REQUEST;
        } else if (pve.hasError(Messages.EMAIL_EXISTS, Messages.USERNAME_EXISTS)) {
          status = Response.Status.CONFLICT;
        }

        return account
            .setErrors(status, errors)
            .setProfileFormData(formData)
            .createResponse(AccountPages.ACCOUNT);
      }
    } catch (ReadOnlyException e) {
      setReferrerOnPage();
      return account
          .setError(Response.Status.BAD_REQUEST, Messages.READ_ONLY_USER)
          .setProfileFormData(formData)
          .createResponse(AccountPages.ACCOUNT);
    }

    event.success();
    setReferrerOnPage();
    return account.setSuccess(Messages.ACCOUNT_UPDATED).createResponse(AccountPages.ACCOUNT);
  }

  /**
   * Processes the logout of user sessions, terminating active sessions.
   *
   * @return A Response object indicating the result of processing the sessions logout.
   */
  @Path("sessions")
  @POST
  public Response processSessionsLogout() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login("sessions");
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);

    UserModel user = auth.getUser();

    // Rather decrease time a bit. To avoid situation when user is immediatelly redirected to login
    // screen, then automatically authenticated (eg. with Kerberos) and then seeing issues due the
    // stale token
    // as time on the token will be same like notBefore
    session.users().setNotBeforeForUser(realm, user, Time.currentTime() - 1);

    session
        .sessions()
        .getUserSessionsStream(realm, user)
        .collect(
            Collectors
                .toList()) // collect to avoid concurrent modification as backchannelLogout removes
        // the user sessions.
        .forEach(
            userSession ->
                AuthenticationManager.backchannelLogout(
                    session,
                    realm,
                    userSession,
                    session.getContext().getUri(),
                    clientConnection,
                    headers,
                    true));

    UriBuilder builder =
        AccountUrls.accountBase(session.getContext().getUri().getBaseUri())
            .path(AccountFormService.class, "sessionsPage");
    String referrer = session.getContext().getUri().getQueryParameters().getFirst(REFERRER);
    if (referrer != null) {
      builder.queryParam(REFERRER, referrer);
    }
    URI location = builder.build(realm.getName());
    return Response.seeOther(location).build();
  }

  /**
   * Processes the revocation of grants for a specific client application.
   *
   * @return A Response object indicating the result of processing the grant revocation.
   */
  @Path("applications")
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response processRevokeGrant() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login("applications");
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);

    String clientId = formData.getFirst("clientId");
    if (clientId == null) {
      setReferrerOnPage();
      return account
          .setError(Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND)
          .createResponse(AccountPages.APPLICATIONS);
    }
    ClientModel client = realm.getClientById(clientId);
    if (client == null) {
      setReferrerOnPage();
      return account
          .setError(Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND)
          .createResponse(AccountPages.APPLICATIONS);
    }

    // Revoke grant in UserModel
    UserModel user = auth.getUser();
    UserConsentManager.revokeConsentToClient(session, client, user);

    event
        .event(EventType.REVOKE_GRANT)
        .client(auth.getClient())
        .user(auth.getUser())
        .detail(Details.REVOKED_CLIENT, client.getClientId())
        .success();
    setReferrerOnPage();

    UriBuilder builder =
        AccountUrls.accountBase(session.getContext().getUri().getBaseUri())
            .path(AccountFormService.class, "applicationsPage");
    String referrer = session.getContext().getUri().getQueryParameters().getFirst(REFERRER);
    if (referrer != null) {
      builder.queryParam(REFERRER, referrer);
    }
    URI location = builder.build(realm.getName());
    return Response.seeOther(location).build();
  }

  /**
   * Processes the update for Time-based One-Time Password (TOTP) configuration.
   *
   * @return A Response object indicating the result of processing the TOTP update.
   */
  @Path("totp")
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response processTotpUpdate() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login("totp");
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);

    account.setAttribute(
        "mode", session.getContext().getUri().getQueryParameters().getFirst("mode"));

    String action = formData.getFirst("submitAction");
    if (action != null && action.equals("Cancel")) {
      setReferrerOnPage();
      return account.createResponse(AccountPages.TOTP);
    }

    csrfCheck(formData);

    UserModel user = auth.getUser();

    if (action != null && action.equals("Delete")) {
      String credentialId = formData.getFirst("credentialId");
      if (credentialId == null) {
        setReferrerOnPage();
        return account
            .setError(Status.OK, Messages.UNEXPECTED_ERROR_HANDLING_REQUEST)
            .createResponse(AccountPages.TOTP);
      }
      user.credentialManager().removeStoredCredentialById(credentialId);
      event.event(EventType.REMOVE_TOTP).client(auth.getClient()).user(auth.getUser()).success();
      setReferrerOnPage();
      return account.setSuccess(Messages.SUCCESS_TOTP_REMOVED).createResponse(AccountPages.TOTP);
    } else {
      String challengeResponse = formData.getFirst("totp");
      String totpSecret = formData.getFirst("totpSecret");
      String userLabel = formData.getFirst("userLabel");

      OTPPolicy policy = realm.getOTPPolicy();
      OTPCredentialModel credentialModel =
          OTPCredentialModel.createFromPolicy(realm, totpSecret, userLabel);
      if (Validation.isBlank(challengeResponse)) {
        setReferrerOnPage();
        return account.setError(Status.OK, Messages.MISSING_TOTP).createResponse(AccountPages.TOTP);
      } else if (!CredentialValidation.validOTP(
          challengeResponse, credentialModel, policy.getLookAheadWindow())) {
        setReferrerOnPage();
        return account.setError(Status.OK, Messages.INVALID_TOTP).createResponse(AccountPages.TOTP);
      }

      if (!CredentialHelper.createOTPCredential(
          session, realm, user, challengeResponse, credentialModel)) {
        setReferrerOnPage();
        return account.setError(Status.OK, Messages.INVALID_TOTP).createResponse(AccountPages.TOTP);
      }
      event.event(EventType.UPDATE_TOTP).client(auth.getClient()).user(auth.getUser()).success();

      setReferrerOnPage();
      return account.setSuccess(Messages.SUCCESS_TOTP).createResponse(AccountPages.TOTP);
    }
  }

  /**
   * Processes a password update based on the submitted form data.
   *
   * @return A Response object indicating the result of processing the password update.
   */
  @Path(PSSWD)
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response processPasswordUpdate() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login(PSSWD);
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);

    csrfCheck(formData);
    UserModel user = auth.getUser();

    boolean requireCurrent = isPasswordSet(user);
    account.setPasswordSet(requireCurrent);

    String password = formData.getFirst(PSSWD);
    String passwordNew = formData.getFirst("password-new");
    String passwordConfirm = formData.getFirst("password-confirm");

    EventBuilder errorEvent =
        event
            .clone()
            .event(EventType.UPDATE_PASSWORD_ERROR)
            .client(auth.getClient())
            .user(auth.getSession().getUser());

    if (requireCurrent) {
      if (Validation.isBlank(password)) {
        setReferrerOnPage();
        errorEvent.error(Errors.PASSWORD_MISSING);
        return account
            .setError(Status.OK, Messages.MISSING_PASSWORD)
            .createResponse(AccountPages.PASSWORD);
      }

      UserCredentialModel cred = UserCredentialModel.password(password);
      if (!user.credentialManager().isValid(cred)) {
        setReferrerOnPage();
        errorEvent.error(Errors.INVALID_USER_CREDENTIALS);
        return account
            .setError(Status.OK, Messages.INVALID_PASSWORD_EXISTING)
            .createResponse(AccountPages.PASSWORD);
      }
    }

    if (Validation.isBlank(passwordNew)) {
      setReferrerOnPage();
      errorEvent.error(Errors.PASSWORD_MISSING);
      return account
          .setError(Status.OK, Messages.MISSING_PASSWORD)
          .createResponse(AccountPages.PASSWORD);
    }

    if (!passwordNew.equals(passwordConfirm)) {
      setReferrerOnPage();
      errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
      return account
          .setError(Status.OK, Messages.INVALID_PASSWORD_CONFIRM)
          .createResponse(AccountPages.PASSWORD);
    }

    try {
      user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
    } catch (ReadOnlyException mre) {
      setReferrerOnPage();
      errorEvent.error(Errors.NOT_ALLOWED);
      return account
          .setError(Response.Status.BAD_REQUEST, Messages.READ_ONLY_PASSWORD)
          .createResponse(AccountPages.PASSWORD);
    } catch (ModelException me) {
      ServicesLogger.LOGGER.failedToUpdatePassword(me);
      setReferrerOnPage();
      errorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
      return account
          .setError(Response.Status.NOT_ACCEPTABLE, me.getMessage(), me.getParameters())
          .createResponse(AccountPages.PASSWORD);
    } catch (Exception ape) {
      ServicesLogger.LOGGER.failedToUpdatePassword(ape);
      setReferrerOnPage();
      errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
      return account
          .setError(Response.Status.INTERNAL_SERVER_ERROR, ape.getMessage())
          .createResponse(AccountPages.PASSWORD);
    }

    session
        .sessions()
        .getUserSessionsStream(realm, user)
        .filter(s -> !Objects.equals(s.getId(), auth.getSession().getId()))
        .collect(
            Collectors
                .toList()) // collect to avoid concurrent modification as backchannelLogout removes
        // the user sessions.
        .forEach(
            s ->
                AuthenticationManager.backchannelLogout(
                    session,
                    realm,
                    s,
                    session.getContext().getUri(),
                    clientConnection,
                    headers,
                    true));

    event.event(EventType.UPDATE_PASSWORD).client(auth.getClient()).user(auth.getUser()).success();

    setReferrerOnPage();
    return account
        .setPasswordSet(true)
        .setSuccess(Messages.ACCOUNT_PASSWORD_UPDATED)
        .createResponse(AccountPages.PASSWORD);
  }

  /**
   * Processes federated identity updates based on the submitted form data.
   *
   * @return A Response object indicating the result of processing federated identity updates.
   */
  @Path("identity")
  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response processFederatedIdentityUpdate() {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login("identity");
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);
    UserModel user = auth.getUser();

    String action = formData.getFirst("action");
    String providerId = formData.getFirst("providerId");

    // Validate provider and action
    Response validationResponse = validateProviderAndAction(providerId, action);
    if (validationResponse != null) {
      return validationResponse;
    }
    // Process the social action
    AccountSocialAction accountSocialAction = AccountSocialAction.getAction(action);
    if (accountSocialAction == null) {
      setReferrerOnPage();
      return account.setError(Status.OK, Messages.INVALID_FEDERATED_IDENTITY_ACTION)
                                    .createResponse(AccountPages.FEDERATED_IDENTITY);
    }
    switch (accountSocialAction) {
      case ADD:
        return handleAddFederatedIdentity(providerId);
      case REMOVE:
        return handleRemoveFederatedIdentity(user, providerId);
      default:
        throw new IllegalArgumentException();
    }
  }

  /**
   * Validates the provider ID and action.
   *
   * @param providerId The ID of the identity provider.
   * @param action The action to perform.
   * @return A Response object if validation fails, null otherwise.
   */
  private Response validateProviderAndAction(final String providerId, final String action) {
    // Check if provider ID is empty
    if (Validation.isEmpty(providerId)) {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.MISSING_IDENTITY_PROVIDER)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }

    // Check if action is valid
    AccountSocialAction accountSocialAction = AccountSocialAction.getAction(action);
    if (accountSocialAction == null) {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.INVALID_FEDERATED_IDENTITY_ACTION)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }

    // Check if provider exists
    if (!realm
        .getIdentityProvidersStream()
        .anyMatch(model -> Objects.equals(model.getAlias(), providerId))) {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.IDENTITY_PROVIDER_NOT_FOUND)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }

    // Check if user is enabled
    if (!auth.getUser().isEnabled()) {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.ACCOUNT_DISABLED)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }

    return null;
  }

  /**
   * Handles adding a federated identity.
   *
   * @param providerId The ID of the identity provider to add.
   * @return A Response object indicating the result of the operation.
   */
  private Response handleAddFederatedIdentity(final String providerId) {
    String redirectUri =
        UriBuilder.fromUri(
                AccountUrls.accountFederatedIdentityPage(
                    session.getContext().getUri().getBaseUri(), realm.getName()))
            .build()
            .toString();

    try {
      String nonce = UUID.randomUUID().toString();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      String input = nonce + auth.getSession().getId() + client.getClientId() + providerId;
      byte[] check = md.digest(input.getBytes(StandardCharsets.UTF_8));
      String hash = Base64Url.encode(check);
      URI linkUrl =
          AccountUrls.identityProviderLinkRequest(
              this.session.getContext().getUri().getBaseUri(), providerId, realm.getName());
      linkUrl =
          UriBuilder.fromUri(linkUrl)
              .queryParam("nonce", nonce)
              .queryParam("hash", hash)
              .queryParam("client_id", client.getClientId())
              .queryParam("redirect_uri", redirectUri)
              .build();
      return Response.seeOther(linkUrl).build();
    } catch (Exception spe) {
      setReferrerOnPage();
      return account
          .setError(
              Response.Status.INTERNAL_SERVER_ERROR, Messages.IDENTITY_PROVIDER_REDIRECT_ERROR)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }
  }

  /**
   * Handles removing a federated identity.
   *
   * @param user The user model.
   * @param providerId The ID of the identity provider to remove.
   * @return A Response object indicating the result of the operation.
   */
  private Response handleRemoveFederatedIdentity(final UserModel user, final String providerId) {
    FederatedIdentityModel link = session.users().getFederatedIdentity(realm, user, providerId);
    if (link != null) {
      return processLinkRemoval(user, providerId, link);
    } else {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.FEDERATED_IDENTITY_NOT_ACTIVE)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }
  }

  /**
   * Processes the removal of a federated identity link.
   *
   * @param user The user model.
   * @param providerId The ID of the identity provider.
   * @param link The federated identity model.
   * @return A Response object indicating the result of the operation.
   */
  private Response processLinkRemoval(
      final UserModel user, final String providerId, final FederatedIdentityModel link) {
    // Removing last social provider is not possible if you don't have other possibility to
    // authenticate
    if (session.users().getFederatedIdentitiesStream(realm, user).count() > 1
        || user.getFederationLink() != null
        || isPasswordSet(user)) {

      session.users().removeFederatedIdentity(realm, user, providerId);

      LOGGER.debugv(
          "Social provider {0} removed successfully from user {1}", providerId, user.getUsername());

      event
          .event(EventType.REMOVE_FEDERATED_IDENTITY)
          .client(auth.getClient())
          .user(auth.getUser())
          .detail(Details.USERNAME, auth.getUser().getUsername())
          .detail(Details.IDENTITY_PROVIDER, link.getIdentityProvider())
          .detail(Details.IDENTITY_PROVIDER_USERNAME, link.getUserName())
          .success();

      setReferrerOnPage();
      return account
          .setSuccess(Messages.IDENTITY_PROVIDER_REMOVED)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    } else {
      setReferrerOnPage();
      return account
          .setError(Status.OK, Messages.FEDERATED_IDENTITY_REMOVING_LAST_PROVIDER)
          .createResponse(AccountPages.FEDERATED_IDENTITY);
    }
  }

  /**
   * Retrieves the resources page.
   *
   * @param resourceId The ID of the resource (optional).
   * @return A Response object indicating the result of navigating to the resources page.
   */
  @Path(RESOURCE)
  @GET
  public Response resourcesPage(@QueryParam("resource_id") final String resourceId) {
    return forwardToPage(RESOURCE, AccountPages.RESOURCES);
  }

  /**
   * Retrieves the resource detail page.
   *
   * @param resourceId The ID of the resource.
   * @return A Response object indicating the result of navigating to the resource detail page.
   */
  @Path("resource/{resource_id}")
  @GET
  public Response resourceDetailPage(@PathParam("resource_id") final String resourceId) {
    return forwardToPage(RESOURCE, AccountPages.RESOURCE_DETAIL);
  }

  /**
   * Retrieves the resource detail page after granting permissions.
   *
   * @param resourceId The ID of the resource.
   * @return A Response object indicating the result of navigating to the resource detail page.
   */
  @Path("resource/{resource_id}/grant")
  @GET
  public Response resourceDetailPageAfterGrant(@PathParam("resource_id") final String resourceId) {
    return resourceDetailPage(resourceId);
  }

  /**
   * Grants or revokes permissions for the specified resource.
   *
   * @param resourceId    The ID of the resource for which permissions are granted or revoked.
   * @param action        The action to perform, such as "grant" or "revoke".
   * @param permissionId  The array of permission IDs to be granted or revoked.
   * @param requester     The username of the user requesting the action.
   * @return A Response object indicating the result of the action.
   */
  @Path("resource/{resource_id}/grant")
  @POST
  public Response grantPermission(
      @PathParam("resource_id") final String resourceId,
      @FormParam("action") final String action,
      @FormParam("permission_id") final String[] permissionId,
      @FormParam("requester") final String requester) {
    // Validate request and get authorization components
    PermissionValidationResult validationResult = validatePermissionRequest(resourceId, action);
    if (validationResult.getErrorResponse() != null) {
      return validationResult.getErrorResponse();
    }

    AuthorizationProvider authorization = validationResult.getAuthorization();
    Resource resource = validationResult.getResource();

    // Process the permission action
    boolean isRevoke = "revoke".equals(action);
    boolean isRevokePolicy = "revokePolicy".equals(action);
    boolean isRevokePolicyAll = "revokePolicyAll".equals(action);

    if (isRevokePolicy || isRevokePolicyAll) {
      handlePolicyRevocation(authorization, permissionId, isRevokePolicyAll);
    } else {
      handlePermissionTickets(authorization, resource, action, permissionId, requester);
    }

    // Return appropriate response based on action
    if (isRevoke || isRevokePolicy || isRevokePolicyAll) {
      return forwardToPage(RESOURCE, AccountPages.RESOURCE_DETAIL);
    }

    return forwardToPage(RESOURCE, AccountPages.RESOURCES);
  }

  /**
   * Validates the permission request and retrieves necessary components.
   *
   * @param resourceId The ID of the resource.
   * @param action The action to perform.
   * @return A PermissionValidationResult containing validation results and components.
   */
  private PermissionValidationResult validatePermissionRequest(
      final String resourceId, final String action) {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return new PermissionValidationResult(login(RESOURCE));
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);

    AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
    Resource resource =
        authorization.getStoreFactory().getResourceStore().findById(null, resourceId);
    if (resource == null) {
      Response errorResponse = Response.status(Response.Status.BAD_REQUEST)
          .entity(INVALID_RESOURCE)
          .build();
      return new PermissionValidationResult(errorResponse);
    }

    if (action == null) {
      throw ErrorResponse.error("Invalid action", Response.Status.BAD_REQUEST);
    }

    return new PermissionValidationResult(authorization, resource);
  }

  /**
   * Handles policy revocation operations.
   *
   * @param authorization The authorization provider.
   * @param permissionId The array of permission IDs.
   * @param isRevokePolicyAll Whether to revoke all policy scopes.
   */
  private void handlePolicyRevocation(
      final AuthorizationProvider authorization,
      final String[] permissionId,
      final boolean isRevokePolicyAll) {
    // Extract policy from permission IDs
    PolicyRevocationContext context = extractPolicyFromPermissionIds(authorization, permissionId);
    PolicyStore policyStore = context.getPolicyStore();
    ResourceServer resourceServer = context.getResourceServer();
    Policy policy = context.getPolicy();
    List<String> remainingIds = context.getRemainingIds();

    // Process policy scopes
    if (policy != null) {
      if (isRevokePolicyAll) {
        removeAllPolicyScopes(policy);
      } else {
        Set<Scope> scopesToKeep = getScopesToKeep(authorization, resourceServer, remainingIds);
        removeScopesNotInSet(policy, scopesToKeep);
      }

      // Clean up empty policy
      if (policy.getScopes().isEmpty()) {
        deleteAssociatedPolicies(policyStore, policy);
      }
    }
  }

  /**
   * Extracts policy from permission IDs.
   *
   * @param authorization The authorization provider.
   * @param permissionId The array of permission IDs.
   * @return A PolicyRevocationContext containing the extracted policy and related components.
   */
  private PolicyRevocationContext extractPolicyFromPermissionIds(
      final AuthorizationProvider authorization, final String[] permissionId) {
    List<String> ids = new ArrayList<>(Arrays.asList(permissionId));
    Iterator<String> iterator = ids.iterator();
    PolicyStore policyStore = authorization.getStoreFactory().getPolicyStore();
    ResourceServer resourceServer =
        authorization.getStoreFactory().getResourceServerStore().findByClient(client);
    Policy policy = null;

    while (iterator.hasNext()) {
      String id = iterator.next();

      if (!id.contains(":")) {
        policy = policyStore.findById(resourceServer, id);
        iterator.remove();
        break;
      }
    }

    return new PolicyRevocationContext(policyStore, resourceServer, policy, ids);
  }

  /**
   * Removes all scopes from a policy.
   *
   * @param policy The policy to modify.
   */
  private void removeAllPolicyScopes(final Policy policy) {
    for (Scope scope : policy.getScopes()) {
      policy.removeScope(scope);
    }
  }

  /**
   * Gets the set of scopes to keep based on the remaining IDs.
   *
   * @param authorization The authorization provider.
   * @param resourceServer The resource server.
   * @param remainingIds The list of remaining IDs.
   * @return A set of scopes to keep.
   */
  private Set<Scope> getScopesToKeep(
      final AuthorizationProvider authorization,
      final ResourceServer resourceServer,
      final List<String> remainingIds) {
    Set<Scope> scopesToKeep = new HashSet<>();

    for (String id : remainingIds) {
      scopesToKeep.add(
          authorization
              .getStoreFactory()
              .getScopeStore()
              .findById(resourceServer, id.split(":")[1]));
    }

    return scopesToKeep;
  }

  /**
   * Removes scopes not in the specified set from a policy.
   *
   * @param policy The policy to modify.
   * @param scopesToKeep The set of scopes to keep.
   */
  private void removeScopesNotInSet(final Policy policy, final Set<Scope> scopesToKeep) {
    for (Scope scope : policy.getScopes()) {
      if (!scopesToKeep.contains(scope)) {
        policy.removeScope(scope);
      }
    }
  }

  /**
   * Deletes all policies associated with the specified policy.
   *
   * @param policyStore The policy store.
   * @param policy The policy whose associated policies should be deleted.
   */
  private void deleteAssociatedPolicies(final PolicyStore policyStore, final Policy policy) {
    for (Policy associated : policy.getAssociatedPolicies()) {
      policyStore.delete(associated.getId());
    }

    policyStore.delete(policy.getId());
  }

  /**
   * Handles permission ticket operations.
   *
   * @param authorization The authorization provider.
   * @param resource The resource.
   * @param action The action to perform.
   * @param permissionId The array of permission IDs.
   * @param requester The username of the requester.
   */
  private void handlePermissionTickets(
      final AuthorizationProvider authorization,
      final Resource resource,
      final String action,
      final String[] permissionId,
      final String requester) {
    PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();
    boolean isGrant = "grant".equals(action);
    boolean isDeny = "deny".equals(action);
    boolean isRevoke = "revoke".equals(action);

    // Create filters for finding tickets
    Map<PermissionTicket.FilterOption, String> filters = createTicketFilters(
        resource, requester, isRevoke);

    // Process tickets
    List<PermissionTicket> tickets =
        ticketStore.find(resource.getResourceServer(), filters, null, null);
    List<PermissionTicket> ticketsToDelete = processTickets(
        tickets, isGrant, isDeny, isRevoke, permissionId);

    // Delete tickets
    for (PermissionTicket ticket : ticketsToDelete) {
      ticketStore.delete(ticket.getId());
    }
  }

  /**
   * Creates filters for finding permission tickets.
   *
   * @param resource The resource.
   * @param requester The username of the requester.
   * @param isRevoke Whether this is a revoke operation.
   * @return A map of filter options.
   */
  private Map<PermissionTicket.FilterOption, String> createTicketFilters(
      final Resource resource, final String requester, final boolean isRevoke) {
    Map<PermissionTicket.FilterOption, String> filters =
        new EnumMap<>(PermissionTicket.FilterOption.class);

    filters.put(PermissionTicket.FilterOption.RESOURCE_ID, resource.getId());
    filters.put(
        PermissionTicket.FilterOption.REQUESTER,
        session.users().getUserByUsername(realm, requester).getId());

    if (isRevoke) {
      filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.TRUE.toString());
    } else {
      filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.FALSE.toString());
    }

    return filters;
  }

  /**
   * Processes tickets based on the specified action.
   *
   * @param tickets The list of tickets to process.
   * @param isGrant Whether this is a grant operation.
   * @param isDeny Whether this is a deny operation.
   * @param isRevoke Whether this is a revoke operation.
   * @param permissionId The array of permission IDs.
   * @return A list of tickets to delete.
   */
  private List<PermissionTicket> processTickets(
      final List<PermissionTicket> tickets,
      final boolean isGrant,
      final boolean isDeny,
      final boolean isRevoke,
      final String[] permissionId) {
    List<PermissionTicket> ticketsToDelete = new ArrayList<>();

    for (PermissionTicket ticket : tickets) {
      if (shouldSkipTicket(ticket, isGrant, permissionId)) {
        continue;
      }

      if (isGrant && !ticket.isGranted()) {
        ticket.setGrantedTimestamp(System.currentTimeMillis());
        ticketsToDelete.add(ticket);
      } else if (shouldDeleteTicket(ticket, isDeny, isRevoke, permissionId)) {
        ticketsToDelete.add(ticket);
      }
    }

    return ticketsToDelete;
  }

  /**
   * Determines whether a ticket should be skipped during processing.
   *
   * @param ticket The permission ticket.
   * @param isGrant Whether this is a grant operation.
   * @param permissionId The array of permission IDs.
   * @return True if the ticket should be skipped, false otherwise.
   */
  private boolean shouldSkipTicket(
      final PermissionTicket ticket,
      final boolean isGrant,
      final String[] permissionId) {
    return isGrant
        && permissionId != null
        && permissionId.length > 0
        && !Arrays.asList(permissionId).contains(ticket.getId());
  }

  /**
   * Determines whether a ticket should be deleted.
   *
   * @param ticket The permission ticket.
   * @param isDeny Whether this is a deny operation.
   * @param isRevoke Whether this is a revoke operation.
   * @param permissionId The array of permission IDs.
   * @return True if the ticket should be deleted, false otherwise.
   */
  private boolean shouldDeleteTicket(
      final PermissionTicket ticket,
      final boolean isDeny,
      final boolean isRevoke,
      final String[] permissionId) {
    return (isDeny || isRevoke)
        && permissionId != null
        && permissionId.length > 0
        && Arrays.asList(permissionId).contains(ticket.getId());
  }

  // PermissionValidationResult moved to a separate file

  // PolicyRevocationContext moved to a separate file

  /**
   * Gets the resource detail page after sharing a resource.
   *
   * @param resourceId The ID of the shared resource.
   * @return A Response object indicating the result of navigating to the resource detail page.
   */
  @Path("resource/{resource_id}/share")
  @GET
  public Response resourceDetailPageAfterShare(@PathParam("resource_id") final String resourceId) {
    return resourceDetailPage(resourceId);
  }

  /**
   * Shares a resource with the specified users and scopes.
   *
   * @param resourceId The ID of the resource to be shared.
   * @param userIds     The array of user IDs with whom to share the resource.
   * @param scopes      The array of scope IDs to be granted when sharing the resource.
   * @return A Response object indicating the result of the sharing operation.
   */
  @Path("resource/{resource_id}/share")
  @POST
  public Response shareResource(
      @PathParam("resource_id") final String resourceId,
      @FormParam("user_id") final String[] userIds,
      @FormParam("scope_id") final String[] scopes) {
    // Validate request and initialize components
    ShareResourceContext context = validateShareResourceRequest(resourceId, userIds);
    if (context.getErrorResponse() != null) {
      return context.getErrorResponse();
    }

    // Process each user
    for (String id : userIds) {
      UserModel user = findUserById(id);
      if (user == null) {
        setReferrerOnPage();
        return account
            .setError(Status.BAD_REQUEST, Messages.INVALID_USER)
            .createResponse(AccountPages.RESOURCE_DETAIL);
      }

      // Process permissions for this user
      processUserPermissions(user, context, scopes);
    }

    return forwardToPage(RESOURCE, AccountPages.RESOURCE_DETAIL);
  }

  /**
   * Validates the share resource request and initializes necessary components.
   *
   * @param resourceId The ID of the resource to be shared.
   * @param userIds The array of user IDs with whom to share the resource.
   * @return A ShareResourceContext containing validation results and components.
   */
  private ShareResourceContext validateShareResourceRequest(
      final String resourceId, final String[] userIds) {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return new ShareResourceContext(login(RESOURCE));
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);

    AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
    PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();
    ScopeStore scopeStore = authorization.getStoreFactory().getScopeStore();
    Resource resource =
        authorization.getStoreFactory().getResourceStore().findById(null, resourceId);

    if (resource == null) {
      throw ErrorResponse.error(INVALID_RESOURCE, Response.Status.BAD_REQUEST);
    }

    if (userIds == null || userIds.length == 0) {
      setReferrerOnPage();
      return new ShareResourceContext(account
          .setError(Status.BAD_REQUEST, Messages.MISSING_PASSWORD)
          .createResponse(AccountPages.PASSWORD));
    }

    ResourceServer resourceServer = resource.getResourceServer();
    return new ShareResourceContext(authorization, ticketStore, scopeStore, resource, resourceServer);
  }

  /**
   * Finds a user by ID, username, or email.
   *
   * @param id The ID, username, or email of the user.
   * @return The user model, or null if not found.
   */
  private UserModel findUserById(final String id) {
    UserModel user = session.users().getUserById(realm, id);

    if (user == null) {
      user = session.users().getUserByUsername(realm, id);
    }

    if (user == null) {
      user = session.users().getUserByEmail(realm, id);
    }

    return user;
  }

  /**
   * Processes permissions for a user.
   *
   * @param user The user model.
   * @param context The share resource context.
   * @param scopes The array of scope IDs.
   */
  private void processUserPermissions(
      final UserModel user,
      final ShareResourceContext context,
      final String[] scopes) {
    Map<PermissionTicket.FilterOption, String> filters =
        new EnumMap<>(PermissionTicket.FilterOption.class);

    filters.put(PermissionTicket.FilterOption.RESOURCE_ID, context.getResource().getId());
    filters.put(PermissionTicket.FilterOption.OWNER, auth.getUser().getId());
    filters.put(PermissionTicket.FilterOption.REQUESTER, user.getId());

    List<PermissionTicket> tickets = context.getTicketStore().find(
        context.getResourceServer(), filters, null, null);
    final String userId = user.getId();

    if (tickets.isEmpty()) {
      createNewPermissions(userId, context, scopes);
    } else if (scopes != null && scopes.length > 0) {
      addMissingScopes(userId, context, scopes, tickets);
    }
  }

  /**
   * Creates new permissions for a user.
   *
   * @param userId The ID of the user.
   * @param context The share resource context.
   * @param scopes The array of scope IDs.
   */
  private void createNewPermissions(
      final String userId,
      final ShareResourceContext context,
      final String[] scopes) {
    if (scopes != null && scopes.length > 0) {
      createPermissionsWithSpecificScopes(userId, context, scopes);
    } else {
      createPermissionsWithDefaultScopes(userId, context);
    }
  }

  /**
   * Creates permissions with specific scopes.
   *
   * @param userId The ID of the user.
   * @param context The share resource context.
   * @param scopes The array of scope IDs.
   */
  private void createPermissionsWithSpecificScopes(
      final String userId,
      final ShareResourceContext context,
      final String[] scopes) {
    for (String scopeId : scopes) {
      Scope scope = context.getScopeStore().findById(context.getResourceServer(), scopeId);
      PermissionTicket ticket = context.getTicketStore().create(
          context.getResourceServer(), context.getResource(), scope, userId);
      ticket.setGrantedTimestamp(System.currentTimeMillis());
    }
  }

  /**
   * Creates permissions with default scopes.
   *
   * @param userId The ID of the user.
   * @param context The share resource context.
   */
  private void createPermissionsWithDefaultScopes(
      final String userId,
      final ShareResourceContext context) {
    if (context.getResource().getScopes().isEmpty()) {
      PermissionTicket ticket = context.getTicketStore().create(
          context.getResourceServer(), context.getResource(), null, userId);
      ticket.setGrantedTimestamp(System.currentTimeMillis());
    } else {
      for (Scope scope : context.getResource().getScopes()) {
        PermissionTicket ticket = context.getTicketStore().create(
            context.getResourceServer(), context.getResource(), scope, userId);
        ticket.setGrantedTimestamp(System.currentTimeMillis());
      }
    }
  }

  /**
   * Adds missing scopes to existing permissions.
   *
   * @param userId The ID of the user.
   * @param context The share resource context.
   * @param scopes The array of scope IDs.
   * @param tickets The list of existing permission tickets.
   */
  private void addMissingScopes(
      final String userId,
      final ShareResourceContext context,
      final String[] scopes,
      final List<PermissionTicket> tickets) {
    List<String> grantScopes = new ArrayList<>(Arrays.asList(scopes));
    Set<String> alreadyGrantedScopes =
        tickets.stream()
            .map(PermissionTicket::getScope)
            .map(Scope::getId)
            .collect(Collectors.toSet());

    grantScopes.removeIf(alreadyGrantedScopes::contains);

    for (String scopeId : grantScopes) {
      Scope scope = context.getScopeStore().findById(context.getResourceServer(), scopeId);
      PermissionTicket ticket = context.getTicketStore().create(
          context.getResourceServer(), context.getResource(), scope, userId);
      ticket.setGrantedTimestamp(System.currentTimeMillis());
    }
  }

  // ShareResourceContext moved to a separate file

  /**
   * Processes resource-related actions, such as canceling or canceling requests for permissions.
   *
   * @param resourceIds The array of resource IDs.
   * @param action      The action to perform, such as "cancel" or "cancelRequest".
   * @return A Response object indicating the result of the action.
   */
  @Path(RESOURCE)
  @POST
  public Response processResourceActions(
      @FormParam("resource_id") final String[] resourceIds, @FormParam("action") final String action) {
    MultivaluedMap<String, String> formData = request.getDecodedFormParameters();

    if (auth == null) {
      return login(RESOURCE);
    }

    auth.require(AccountRoles.MANAGE_ACCOUNT);
    csrfCheck(formData);

    AuthorizationProvider authorization = session.getProvider(AuthorizationProvider.class);
    PermissionTicketStore ticketStore = authorization.getStoreFactory().getPermissionTicketStore();

    if (action == null) {
      throw ErrorResponse.error("Invalid action", Response.Status.BAD_REQUEST);
    }

    for (String resourceId : resourceIds) {
      Resource resource =
          authorization.getStoreFactory().getResourceStore().findById(null, resourceId);

      if (resource == null) {
        throw ErrorResponse.error(INVALID_RESOURCE, Response.Status.BAD_REQUEST);
      }

      Map<PermissionTicket.FilterOption, String> filters =
          new EnumMap<>(PermissionTicket.FilterOption.class);

      filters.put(PermissionTicket.FilterOption.REQUESTER, auth.getUser().getId());
      filters.put(PermissionTicket.FilterOption.RESOURCE_ID, resource.getId());

      if ("cancel".equals(action)) {
        filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.TRUE.toString());
      } else if ("cancelRequest".equals(action)) {
        filters.put(PermissionTicket.FilterOption.GRANTED, Boolean.FALSE.toString());
      }

      for (PermissionTicket ticket
          : ticketStore.find(resource.getResourceServer(), filters, null, null)) {
        ticketStore.delete(ticket.getId());
      }
    }

    return forwardToPage("authorization", AccountPages.RESOURCES);
  }

  /**
   * Builds a UriBuilder for the login redirect URL.
   *
   * @param base The base URI builder.
   * @return The UriBuilder for the login redirect URL.
   */
  public static UriBuilder loginRedirectUrl(final UriBuilder base) {
    return RealmsResource.accountUrl(base).path(AccountFormService.class, "loginRedirect");
  }

  /**
   * Gets the base redirect URI for the account.
   *
   * @return The base redirect URI for the account.
   */
  @Override
  protected URI getBaseRedirectUri() {
    return AccountUrls.accountBase(session.getContext().getUri().getBaseUri())
        .path("/")
        .build(realm.getName());
  }

  /**
   * Checks if a password is set for the user.
   *
   * @param user    The user model.
   * @return {@code true} if a password is set, {@code false} otherwise.
   */
  public static boolean isPasswordSet(final UserModel user) {
    return user.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE);
  }

  private String[] getReferrer() {
    String referrer = session.getContext().getUri().getQueryParameters().getFirst(REFERRER);
    if (referrer == null) {
      return null;
    }

    String referrerUri =
        session.getContext().getUri().getQueryParameters().getFirst("referrer_uri");

    ClientModel referrerClient = realm.getClientByClientId(referrer);
    if (referrerClient != null) {
      if (referrerUri != null) {
        referrerUri = RedirectUtils.verifyRedirectUri(session, referrerUri, referrerClient);
      } else {
        referrerUri =
            ResolveRelative.resolveRelativeUri(
                session, referrerClient.getRootUrl(), referrerClient.getBaseUrl());
      }

      if (referrerUri != null) {
        String referrerName = referrerClient.getName();
        if (Validation.isBlank(referrerName)) {
          referrerName = referrer;
        }
        return new String[] {referrerName, referrerUri};
      }
    } else if (referrerUri != null && client != null) {
      referrerUri = RedirectUtils.verifyRedirectUri(session, referrerUri, client);

      if (referrerUri != null) {
        return new String[] {referrer, referrerUri};
      }
    }

    return null;
  }

  private enum AccountSocialAction {
    /** Add action. */
    ADD,

    /** Remove action. */
    REMOVE;

    public static AccountSocialAction getAction(final String action) {
      if ("add".equalsIgnoreCase(action)) {
        return ADD;
      } else if ("remove".equalsIgnoreCase(action)) {
        return REMOVE;
      } else {
        return null;
      }
    }
  }

  private void csrfCheck(final MultivaluedMap<String, String> formData) {
    String formStateChecker = formData.getFirst("stateChecker");
    if (formStateChecker == null || !formStateChecker.equals(this.stateChecker)) {
      throw new ForbiddenException();
    }
  }
}
