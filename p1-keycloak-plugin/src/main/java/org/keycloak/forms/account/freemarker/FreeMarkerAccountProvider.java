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
package org.keycloak.forms.account.freemarker;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.forms.account.AccountPages;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.account.freemarker.model.AccountBean;
import org.keycloak.forms.account.freemarker.model.AccountFederatedIdentityBean;
import org.keycloak.forms.account.freemarker.model.ApplicationsBean;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean;
import org.keycloak.forms.account.freemarker.model.FeaturesBean;
import org.keycloak.forms.account.freemarker.model.LogBean;
import org.keycloak.forms.account.freemarker.model.PasswordBean;
import org.keycloak.forms.account.freemarker.model.RealmBean;
import org.keycloak.forms.account.freemarker.model.ReferrerBean;
import org.keycloak.forms.account.freemarker.model.SessionsBean;
import org.keycloak.forms.account.freemarker.model.TotpBean;
import org.keycloak.forms.account.freemarker.model.UrlBean;
import org.keycloak.forms.login.MessageType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.theme.FreeMarkerException;
import org.keycloak.theme.Theme;
import org.keycloak.theme.beans.AdvancedMessageFormatterMethod;
import org.keycloak.theme.beans.LocaleBean;
import org.keycloak.theme.beans.MessageBean;
import org.keycloak.theme.beans.MessageFormatterMethod;
import org.keycloak.theme.beans.MessagesPerFieldBean;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.StringUtil;

/**
 * Implementation of the {@link AccountProvider} interface using FreeMarker for rendering account-related pages.
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class FreeMarkerAccountProvider implements AccountProvider {

  /** Logger for logging messages. */
  private static final Logger LOGGER = Logger.getLogger(FreeMarkerAccountProvider.class);

  /** The user model representing the user for whom the account-related pages are being rendered. */
  private UserModel user;

  /** Form data containing profile information. */
  private MultivaluedMap<String, String> profileFormData;

  /** HTTP response status. */
  private Response.Status status = Response.Status.OK;

  /** The realm model representing the Keycloak realm. */
  private RealmModel realm;

  /** Referrer information for the account provider. */
  private String[] referrer;

  /** List of events associated with the user. */
  private List<Event> events;

  /** State checker used in account-related operations. */
  private String stateChecker;

  /** ID token hint for account-related operations. */
  private String idTokenHint;

  /** List of user sessions. */
  private List<UserSessionModel> sessions;

  /** Flag indicating whether the identity provider is enabled. */
  private boolean identityProviderEnabled;

  /** Flag indicating whether events are enabled. */
  private boolean eventsEnabled;

  /** Flag indicating whether password updates are supported. */
  private boolean passwordUpdateSupported;

  /** Flag indicating whether a password is set. */
  private boolean passwordSet;

  /** The Keycloak session associated with this account provider. */
  private KeycloakSession session;

  /** The FreeMarker provider for processing templates. */
  private FreeMarkerProvider freeMarker;

  /** Map of additional attributes used in rendering templates. */
  private Map<String, Object> attributes;

  /** UriInfo representing the URI information. */
  private UriInfo uriInfo;

  /** List of form messages representing errors, warnings, or other messages. */
  private List<FormMessage> messages = null;

  /** Message type indicating the severity of messages (e.g., ERROR, WARNING, SUCCESS). */
  private MessageType messageType = MessageType.ERROR;

  /** Flag indicating whether authorization is supported. */
  private boolean authorizationSupported;

  /**
   * Constructs a new instance of {@code FreeMarkerAccountProvider}.
   *
   * @param keycloakSession The Keycloak session.
   */
  public FreeMarkerAccountProvider(final KeycloakSession keycloakSession) {
    this.session = keycloakSession;
    this.freeMarker = keycloakSession.getProvider(FreeMarkerProvider.class);
  }

  /**
   * Sets the URI information for the account provider.
   *
   * @param accountUriInfo The URI information to set.
   * @return The updated {@code AccountProvider} instance.
   */
  public AccountProvider setUriInfo(final UriInfo accountUriInfo) {
    this.uriInfo = accountUriInfo;
    return this;
  }

  /**
   * Sets the HTTP headers for the account provider.
   *
   * @param httpHeaders The HTTP headers to set.
   * @return This {@code AccountProvider} instance for method chaining.
   */
  @Override
  public AccountProvider setHttpHeaders(final HttpHeaders httpHeaders) {
    // Sets the HTTP headers for the account provider.
    // headers are never used in this class
    return this;
  }

  /**
   * Creates a response based on the specified account page.
   *
   * @param page The account page.
   * @return The response generated for the specified page.
   */
  @Override
  public Response createResponse(final AccountPages page) {
    Map<String, Object> customAttributes = new HashMap<>();

    if (this.attributes != null) {
      customAttributes.putAll(this.attributes);
    }

    Theme theme;
    try {
      theme = getTheme();
    } catch (IOException e) {
      LOGGER.error("Failed to create theme", e);
      return Response.serverError().build();
    }

    Locale locale = session.getContext().resolveLocale(user);
    Properties messagesBundle = handleThemeResources(theme, locale, customAttributes);

    URI baseUri = uriInfo.getBaseUri();
    UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
    for (Map.Entry<String, List<String>> e : uriInfo.getQueryParameters().entrySet()) {
      baseUriBuilder.queryParam(e.getKey(), e.getValue().toArray());
    }
    URI baseQueryUri = baseUriBuilder.build();

    if (stateChecker != null) {
      customAttributes.put("stateChecker", stateChecker);
    }

    handleMessages(locale, messagesBundle, customAttributes);

    if (referrer != null) {
      customAttributes.put("referrer", new ReferrerBean(referrer));
    }

    if (realm != null) {
      customAttributes.put("realm", new RealmBean(realm));
    }

    customAttributes.put(
        "url",
        new UrlBean(realm, theme, baseUri, baseQueryUri, uriInfo.getRequestUri(), idTokenHint));

    if (realm != null && realm.isInternationalizationEnabled()) {
      UriBuilder b = UriBuilder.fromUri(baseQueryUri).path(uriInfo.getPath());
      customAttributes.put("locale", new LocaleBean(realm, locale, b, messagesBundle));
    }

    customAttributes.put(
        "features",
        new FeaturesBean(
            identityProviderEnabled,
            eventsEnabled,
            passwordUpdateSupported,
            authorizationSupported));
    customAttributes.put("account", new AccountBean(user, profileFormData));

    switch (page) {
      case TOTP:
        customAttributes.put("totp", new TotpBean(session, realm, user, uriInfo.getRequestUriBuilder()));
        break;
      case FEDERATED_IDENTITY:
        customAttributes.put(
          "federatedIdentity",
          new AccountFederatedIdentityBean(
              session, realm, user, uriInfo.getBaseUri(), stateChecker));
        break;
      case LOG:
        customAttributes.put("log", new LogBean(events));
        break;
      case SESSIONS:
        customAttributes.put("sessions", new SessionsBean(realm, sessions));
        break;
      case APPLICATIONS:
        customAttributes.put("applications", new ApplicationsBean(session, realm, user));
        customAttributes.put("advancedMsg", new AdvancedMessageFormatterMethod(locale, messagesBundle));
        break;
      case PASSWORD:
        customAttributes.put("password", new PasswordBean(passwordSet));
        break;
      case RESOURCES:
      case RESOURCE_DETAIL:
        if (realm != null && !realm.isUserManagedAccessAllowed()) {
          return Response.status(Status.FORBIDDEN).build();
        }
        customAttributes.put("authorization", new AuthorizationBean(session, realm, user, uriInfo));
        break;
      default:
        // Handle unknown page or provide a default behavior
        break;
    }

    return processTemplate(theme, page, customAttributes, locale);
  }

  /**
   * Get Theme used for page rendering.
   *
   * @return theme for page rendering, never null
   * @throws IOException in case of Theme loading problem
   */
  protected Theme getTheme() throws IOException {
    return session.theme().getTheme(Theme.Type.ACCOUNT);
  }

  /**
   * Load message bundle and place it into <code>msg</code> template attribute. Also load Theme
   * properties and place them into <code>properties</code> template attribute.
   *
   * @param theme actual Theme to load bundle from
   * @param locale to load bundle for
   * @param customAttributes template attributes to add resources to
   * @return message bundle for other use
   */
  protected Properties handleThemeResources(
      final Theme theme, final Locale locale, final Map<String, Object> customAttributes) {
    Properties messagesBundle = new Properties();
    try {
      if (!StringUtil.isNotBlank(realm.getDefaultLocale())) {
        messagesBundle.putAll(realm.getRealmLocalizationTextsByLocale(realm.getDefaultLocale()));
      }
      messagesBundle.putAll(theme.getMessages(locale));
      messagesBundle.putAll(realm.getRealmLocalizationTextsByLocale(locale.toLanguageTag()));
      customAttributes.put("msg", new MessageFormatterMethod(locale, messagesBundle));
    } catch (IOException e) {
      LOGGER.warn("Failed to load messages", e);
      messagesBundle = new Properties();
    }
    try {
      customAttributes.put("properties", theme.getProperties());
    } catch (IOException e) {
      LOGGER.warn("Failed to load properties", e);
    }
    return messagesBundle;
  }

  /**
   * Handle messages to be shown on the page - set them to template attributes.
   *
   * @param locale to be used for message text loading
   * @param messagesBundle to be used for message text loading
   * @param customAttributes template attributes to messages related info to
   * @see #messageType
   * @see #messages
   */
  protected void handleMessages(
      final Locale locale, final Properties messagesBundle, final Map<String, Object> customAttributes) {
    MessagesPerFieldBean messagesPerField = new MessagesPerFieldBean();
    if (messages != null) {
      MessageBean wholeMessage = new MessageBean(null, messageType);
      for (FormMessage message : this.messages) {
        String formattedMessageText = formatMessage(message, messagesBundle, locale);
        if (formattedMessageText != null) {
          wholeMessage.appendSummaryLine(formattedMessageText);
          messagesPerField.addMessage(message.getField(), formattedMessageText, messageType);
        }
      }
      customAttributes.put("message", wholeMessage);
    }
    customAttributes.put("messagesPerField", messagesPerField);
  }

  /**
   * Process FreeMarker template and prepare Response. Some fields are used for rendering also.
   *
   * @param theme to be used (provided by <code>getTheme()</code>)
   * @param page to be rendered
   * @param customAttributes pushed to the template
   * @param locale to be used
   * @return Response object to be returned to the browser, never null
   */
  protected Response processTemplate(
      final Theme theme, final AccountPages page, final Map<String, Object> customAttributes, final Locale locale) {
    try {
      String result = freeMarker.processTemplate(customAttributes, Templates.getTemplate(page), theme);
      Response.ResponseBuilder builder =
          Response.status(status)
              .type(MediaType.TEXT_HTML_UTF_8_TYPE)
              .language(locale)
              .entity(result);
      builder.cacheControl(CacheControlUtil.noCache());
      return builder.build();
    } catch (FreeMarkerException e) {
      LOGGER.error("Failed to process template", e);
      return Response.serverError().build();
    }
  }

  /**
   * Sets the password set status for the FreeMarker rendering process. The password set status indicates
   * whether the user has already set a password for their account.
   *
   * <p>This method is typically used to customize rendering based on whether the user has completed
   * the initial password setup or if it needs to be addressed.
   *
   * @param passwordDefined A boolean value indicating whether the user has set a password.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   */
  public AccountProvider setPasswordSet(final boolean passwordDefined) {
    this.passwordSet = passwordDefined;
    return this;
  }

  /**
   * Sets a message with a specified type for the FreeMarker rendering process. Messages can be of three
   * types: SUCCESS, WARNING, and ERROR. These messages are used to provide feedback to users based on
   * the result or status of a specific operation.
   *
   * <p>The method creates a new message and associates it with the specified type, allowing customization
   * of the rendering based on the nature of the message.
   *
   * @param type        The type of the message (SUCCESS, WARNING, or ERROR).
   * @param message     The message text to set.
   * @param parameters  Optional parameters to be included in the formatted message.
   */
  protected void setMessage(final MessageType type, final String message, final Object... parameters) {
    messageType = type;
    messages = new ArrayList<>();
    messages.add(new FormMessage(null, message, parameters));
  }

  /**
   * Formats a message using the provided FormMessage, messages bundle, and locale.
   *
   * <p>This method is responsible for taking a FormMessage, retrieving its corresponding message
   * text from the messages bundle, and formatting the message using the specified locale.
   *
   * @param message         The FormMessage to be formatted.
   * @param messagesBundle  The messages bundle containing message texts.
   * @param locale          The locale used for formatting the message.
   * @return The formatted message or the original message text if formatting fails.
   */
  protected String formatMessage(final FormMessage message, final Properties messagesBundle, final Locale locale) {
    if (message == null) {
      return null;
    }
    if (messagesBundle.containsKey(message.getMessage())) {
      return new MessageFormat(messagesBundle.getProperty(message.getMessage()), locale)
          .format(message.getParameters());
    } else {
      return message.getMessage();
    }
  }

  /**
   * Sets a list of error messages for the FreeMarker rendering process. Error messages can be used to
   * communicate to users that a specific operation or action has encountered multiple issues or failures.
   *
   * <p>Error messages set using this method are typically displayed to users to inform them about
   * critical issues that may need attention or action. This method allows setting multiple error
   * messages, each associated with a specific form field or aspect.
   *
   * @param responseStatus   The HTTP response status associated with the errors.
   * @param errorMessages    The list of error messages to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see FormMessage
   */
  @Override
  public AccountProvider setErrors(final Response.Status responseStatus, final List<FormMessage> errorMessages) {
    this.status = responseStatus;
    this.messageType = MessageType.ERROR;
    this.messages = new ArrayList<>(errorMessages);
    return this;
  }

  /**
   * Sets an error message for the FreeMarker rendering process. Error messages can be used to
   * communicate to users that a specific operation or action has encountered an issue or failure.
   *
   * <p>Error messages set using this method are typically displayed to users to inform them about
   * critical issues that may need attention or action.
   *
   * @param responseStatus   The HTTP response status associated with the error.
   * @param errorMessage     The error message to set.
   * @param parameters  Optional parameters to be included in the formatted error message.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   */
  @Override
  public AccountProvider setError(
      final Response.Status responseStatus, final String errorMessage, final Object... parameters) {
    this.status = responseStatus;
    setMessage(MessageType.ERROR, errorMessage, parameters);
    return this;
  }

  /**
   * Sets a success message for the FreeMarker rendering process. Success messages can be used to
   * provide users with positive feedback or confirmations of successful actions.
   *
   * <p>Success messages set using this method are typically displayed to users to acknowledge that
   * a specific operation or action has been completed successfully.
   *
   * @param message     The success message to set.
   * @param parameters  Optional parameters to be included in the formatted success message.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   */
  @Override
  public AccountProvider setSuccess(final String message, final Object... parameters) {
    setMessage(MessageType.SUCCESS, message, parameters);
    return this;
  }

  /**
   * Sets a warning message for the FreeMarker rendering process. Warning messages can be used to
   * provide users with important information or alerts without halting the rendering process.
   *
   * <p>Warning messages set using this method are typically displayed to users to inform them about
   * non-critical issues or actions they may need to take.
   *
   * @param message     The warning message to set.
   * @param parameters  Optional parameters to be included in the formatted warning message.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   */
  @Override
  public AccountProvider setWarning(final String message, final Object... parameters) {
    setMessage(MessageType.WARNING, message, parameters);
    return this;
  }

  /**
   * Sets the user model for the FreeMarker rendering process. The user model represents the details
   * and attributes of the user account, and it can be used to customize rendering based on user-specific
   * information.
   *
   * <p>The user model is typically employed to tailor the presentation of content specific to the user,
   * such as personalized greetings, user-specific details, or account-related information.
   *
   * @param userModel The user model to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see UserModel
   */
  @Override
  public AccountProvider setUser(final UserModel userModel) {
    this.user = userModel;
    return this;
  }

  /**
   * Sets the profile form data for the FreeMarker rendering process. Profile form data represents
   * user-specific information collected from a form, and it can be used to customize rendering
   * based on the user's profile data.
   *
   * <p>The profile form data is typically employed to tailor the presentation of content that is
   * specific to the user's profile information or to include personalized details in the rendered
   * output.
   *
   * @param formData The multivalued map containing profile form data.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see MultivaluedMap
   */
  @Override
  public AccountProvider setProfileFormData(final MultivaluedMap<String, String> formData) {
    this.profileFormData = formData;
    return this;
  }

  /**
   * Sets the realm information for the FreeMarker rendering process. The realm represents the security
   * domain or scope within the application, and it can be used to customize rendering based on the
   * current realm context.
   *
   * <p>The realm information is often used to tailor the rendering of content specific to a security
   * domain or to provide context-aware features based on the user's realm.
   *
   * @param realmModel The realm model to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see RealmModel
   */
  @Override
  public AccountProvider setRealm(final RealmModel realmModel) {
    this.realm = realmModel;
    return this;
  }

  /**
   * Sets the referrer information for the FreeMarker rendering process. The referrer is a piece of
   * information indicating the source or origin of a request, and it can be used to customize
   * rendering based on the referring source.
   *
   * <p>The referrer information is often utilized to tailor the presentation of content based on
   * the context or origin from which a user arrived at a particular page.
   *
   * @param referrerSource The array of referrer strings to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   */
  @Override
  public AccountProvider setReferrer(final String[] referrerSource) {
    this.referrer = referrerSource;
    return this;
  }

  /**
   * Sets the events for the FreeMarker rendering process. Events represent specific occurrences or
   * actions within the application and can be used to customize rendering based on event information.
   *
   * <p>The events are typically employed to provide insights into user activities or trigger
   * rendering behavior based on changes in the application state.
   *
   * @param eventsInfo The list of events to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see Event
   */
  @Override
  public AccountProvider setEvents(final List<Event> eventsInfo) {
    this.events = eventsInfo;
    return this;
  }

  /**
   * Sets the user sessions for the FreeMarker rendering process. User sessions represent the active
   * sessions associated with a user account and can be used to customize rendering based on session
   * information.
   *
   * <p>The user sessions are typically utilized when rendering user-specific content or providing
   * information about active sessions.
   *
   * @param userSessions The list of user sessions to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see UserSessionModel
   */
  @Override
  public AccountProvider setSessions(final List<UserSessionModel> userSessions) {
    this.sessions = userSessions;
    return this;
  }

  /**
   * Sets the state checker for the FreeMarker rendering process. The state checker is a piece of
   * information that can be used to customize rendering based on a specific state or condition.
   *
   * <p>The state checker is typically employed in scenarios where rendering behavior needs to be
   * adjusted based on the state of the application or user interaction.
   *
   * @param stateCheckerInfo The state checker to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see <a href="https://example-docs.com/state-checker">State Checker Documentation</a>
   */
  @Override
  public AccountProvider setStateChecker(final String stateCheckerInfo) {
    this.stateChecker = stateCheckerInfo;
    return this;
  }

  /**
   * Sets the ID token hint for the FreeMarker rendering process. The ID token hint is a piece
   * of information that can be used to influence the rendering behavior based on the context
   * of an identity token.
   *
   * <p>The ID token hint is typically used in scenarios where additional information from an
   * identity token is needed for rendering purposes.
   *
   * @param idTokenHintInfo The ID token hint to set.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect Core</a>
   */
  @Override
  public AccountProvider setIdTokenHint(final String idTokenHintInfo) {
    this.idTokenHint = idTokenHintInfo;
    return this;
  }

  /**
   * Sets various features and options for the FreeMarker rendering process, allowing customization
   * of the rendering behavior based on specific capabilities or requirements.
   *
   * @param identityProviderFeatureEnabled     Flag indicating whether identity provider features are enabled.
   * @param eventsHandlingEnabled              Flag indicating whether events handling is enabled.
   * @param passwordUpdateFeatureSupported     Flag indicating whether password update is supported.
   * @param authorizationFeatureSupported      Flag indicating whether authorization features are supported.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see FeaturesBean
   */
  @Override
  public AccountProvider setFeatures(
      final boolean identityProviderFeatureEnabled,
      final boolean eventsHandlingEnabled,
      final boolean passwordUpdateFeatureSupported,
      final boolean authorizationFeatureSupported) {
    this.identityProviderEnabled = identityProviderFeatureEnabled;
    this.eventsEnabled = eventsHandlingEnabled;
    this.passwordUpdateSupported = passwordUpdateFeatureSupported;
    this.authorizationSupported = authorizationFeatureSupported;
    return this;
  }

  /**
   * Sets a custom attribute for the FreeMarker rendering process. Custom attributes can be used
   * to provide additional data to the FreeMarker templates and customize the rendering behavior.
   *
   * <p>Attributes set using this method will be accessible within the FreeMarker templates.
   *
   * @param key   The key of the custom attribute.
   * @param value The value associated with the custom attribute.
   * @return This {@code FreeMarkerAccountProvider} instance for method chaining.
   *
   * @see <a href="https://freemarker.apache.org/">FreeMarker Documentation</a>
   */
  @Override
  public AccountProvider setAttribute(final String key, final String value) {
    if (attributes == null) {
      attributes = new HashMap<>();
    }
    attributes.put(key, value);
    return this;
  }

  /**
   * Closes the account provider.
   */
  @Override
  public void close() {
    // Closes the account provider.
  }
}
