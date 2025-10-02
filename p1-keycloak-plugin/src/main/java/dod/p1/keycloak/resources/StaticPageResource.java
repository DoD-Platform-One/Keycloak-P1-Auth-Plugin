package dod.p1.keycloak.resources;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Resource provider that serves static pages rendered from the current LOGIN theme.
 * <p>
 * Only templates explicitly listed in {@code allowedTemplates} can be requested, so path traversal
 * or arbitrary file access is prevented. The class is {@code final} because it is not intended to
 * be subclassed; if you need different behaviour create a new resource provider instead.
 */
@Path("/")
public final class StaticPageResource implements RealmResourceProvider {

    /**
     * Logger for diagnostic messages.
     */
    private static final Logger LOGGER = LogManager.getLogger(StaticPageResource.class);

    /**
     * Whitelist of approved page names that can be accessed.
     */
    private static final java.util.Set<String> APPROVED_PAGES = java.util.Set.of(
            "faq", "supervisor", "mfa-troubleshooting", "employees", "success", "documents");

    /** The current Keycloak session. */
    private final KeycloakSession session;

    /**
     * Creates a new {@code StaticPageResource} bound to the given session.
     *
     * @param keycloakSession the active Keycloak session
     */
    public StaticPageResource(final KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * Render a static page from the LOGIN theme.
     *
     * @param pageName the template base name (without {@code .ftl}) to render; must be whitelisted
     * @return the rendered HTML page, or an error response if the template is not allowed
     */
    @GET
    @Path("{pageName}")
    @Produces(MediaType.TEXT_HTML)
    public Response getPage(@PathParam("pageName") final String pageName) {
        LOGGER.debug("Requested page: {}", pageName);
        if (APPROVED_PAGES.contains(pageName)) {
            return loadTemplateFromLoginTheme(pageName + ".ftl");
        } else {
            LOGGER.warn("Attempted access to non-approved page: {}", pageName);
            return loadTemplateFromLoginTheme("error.ftl");
        }
    }

    /**
     * Renders the given template using Keycloak's built‑in {@link LoginFormsProvider} so the
     * standard data‑model (realm, msg, url, etc.) is available to the template.
     *
     * @param templateName the file name of the template to render, including the {@code .ftl} suffix
     * @return a {@link Response} containing the fully rendered HTML
     */
    private Response loadTemplateFromLoginTheme(final String templateName) {
        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);
        forms.setAttribute("staticPage", Boolean.TRUE);
        try {
            return forms.createForm(templateName);
        } catch (Exception e) {
            LOGGER.error("Failed to process template: {}", templateName, e);
            // Fall back to error template if available, otherwise return a generic error
            try {
                return forms.createForm("error.ftl");
            } catch (Exception fallbackError) {
                LOGGER.error("Failed to load error template as fallback", fallbackError);
                return createErrorResponse(
                        Response.Status.INTERNAL_SERVER_ERROR,
                        "<html><body><h1>Error</h1><p>An error occurred while processing the page.</p></body></html>");
            }
        }
    }

    /**
     * Creates an HTTP error response with HTML content.
     *
     * @param status the HTTP status code to use in the response
     * @param content the HTML content to include in the response body
     * @return a Response object configured with the specified status and HTML content
     */
    private Response createErrorResponse(final Response.Status status, final String content) {
        return Response.status(status)
                .header("Content-Type", MediaType.TEXT_HTML + ";charset=UTF-8")
                .type(MediaType.TEXT_HTML)
                .entity(content)
                .build();
    }
}
