<#import "template-terms.ftl" as layout>
<@layout.registrationLayout displayMessage=true displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
<#if section = "form">
  <#if realm.password>
    <form class="login-form-body flex" onsubmit="login.disabled=true;return true;" action="${url.loginAction}" method="post">
      <div class="form-group">
        <label class="form-label" for="username">
          <#if !realm.loginWithEmailAllowed>${msg("username")}
            <#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}
              <#else>${msg("email")}</#if>
                </label>
                <input tabindex="1" id="username" class="form-control " name="username" placeholder="Your username"
                value="${(login.username!'')}" type="text" autofocus autocomplete="off"/>
      </div>

      <div class="form-group field--password">
        <label for="password" class="form-label">${msg("password")}</label>
        <#if realm.resetPasswordAllowed>
          <a tabindex="5" class="forgot" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
        </#if>
        <input tabindex="2" id="password" class="form-control " name="password" placeholder="Your password"
        type="password" autocomplete="off"/>
      </div>


      <div>
        <p class="mt-0">
        <a href="${url.registrationUrl}">Create account<span class="icon append arrow-right"></span></a></p>
        <p>
        For additional help, visit the <a href="${properties.kcHttpRelativePath!'/auth'}/realms/${realm.name}/onboarding/faq" target="_blank">FAQ page</a> or email us at <a
          id="helpdesk" href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a></p>
      </div>

      <div id="form-buttons" class="form-group form-buttons flex justify-end gap-3 mt-auto">
        <input type="hidden" id="id-hidden-input" name="credentialId"
      <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
        <a class="btn btn-accent outline" name="cancel" href="https://p1.dso.mil">Decline</a>
        <button tabindex="4"
          class="btn btn-primary btn-block"
          name="login" id="kc-login" type="submit">
          <span class="icon prepend lock"></span>Accept terms & continue<span class="icon append arrow-right"></span>
        </button>
      </div>

    </form>
  </#if>
</#if>

</@layout.registrationLayout>

<script>
  const feedback = document.getElementById('alert-error');
  
  // Handle disabled user accounts and access denied messages
  if (feedback && (
    feedback.innerHTML.indexOf('Account is disabled') > -1 ||
    feedback.innerHTML.indexOf('User is disabled') > -1 ||
    feedback.innerHTML.indexOf('account has not been granted access') > -1 ||
    feedback.innerHTML.indexOf('not been granted access to this application') > -1
  )) {
    feedback.outerHTML = [
      '<div class="alert alert-warning" style="background-color: #fff3cd; border-color: #ffeaa7; color: #856404; padding: 1rem; border-radius: 0.375rem; border: 1px solid;">',
      '<p style="margin: 0 0 0.5rem 0; font-weight: bold;">Account Access Issue</p>',
      '<p style="margin: 0 0 0.5rem 0;">Your account has been disabled or does not have access to this application. Please contact the helpdesk for assistance:</p>',
      '<p style="margin: 0;"><a href="mailto:${msg("helpEmail")}" style="color: #856404; text-decoration: underline;">Email helpdesk (${msg("helpEmail")})</a></p>',
      '</div>'
    ].join('');
  }
  
  // Handle CAC detection - make it less prominent and show on hover
  else if (feedback && feedback.innerHTML.indexOf('X509 certificate') > -1 && feedback.innerHTML.indexOf('Invalid user') > -1) {
    // Hide the original CAC message
    feedback.style.display = 'none';
    
    // Add hover tooltip to username field
    const usernameField = document.getElementById('username');
    if (usernameField) {
      usernameField.title = 'DoD PKI/CAC detected. You can register for a new account or login with username/password to associate this CAC.';
      usernameField.classList.add('cac-detected');
    }
  }
</script>
