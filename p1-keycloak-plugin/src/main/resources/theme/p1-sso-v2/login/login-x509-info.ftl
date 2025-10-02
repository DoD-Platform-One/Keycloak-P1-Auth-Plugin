<#import "template-terms.ftl" as layout>
<@layout.registrationLayout; section>
<#if section = "form">
  <form id="kc-x509-login-info" class="" action="${url.loginAction}" method="post">
    <div class="form-group">

      <div class="alert alert-success cac-info">
        <p><b>DoD PKI/CAC Detected</b></p>
        <#if x509.formData??>
          <p class="mt-0">Certificate Details</p>
          <div class="cac-attributes">
            <#list x509.formData?keys as key>
              <div class="cac-attribute">
                <b>${key}:</b>
                <span id="certificate_${key}" class="">
                  <#if x509.formData[key]?is_string>
                    ${x509.formData[key]}
                  <#else>
                    [complex value]
                  </#if>
                </span>
              </div>
            </#list>
          </div>
        <#else>
          <p id="certificate_subjectDN" class="">${msg("noCertificate")}</p>
        </#if>
      </div>
    </div>

    <div class="form-group">

      <#if x509.formData.isUserEnabled??>
        <label for="username" class="inline fw-normal">${msg("doX509Login")}</label>
        <label id="username" class="inline">${(x509.formData.username!'')}</label>
      </#if>

    </div>

    <div class="form-group mt-auto">
      <div id="kc-form-buttons" class="form-buttons">
        <div class="flex justify-end flex-wrap gap-3">
          <#if x509.formData.isUserEnabled??>
            <button class="btn btn-accent outline w-auto" name="cancel" id="kc-cancel" type="submit" value="${msg("doIgnore")}">Decline</button>
          </#if>
          <button class="btn btn-primary w-auto" name="login" id="kc-login" type="submit" value="${msg("doContinue")}" autofocus><span class="icon lock prepend"></span>Accept terms & log in<span class="icon append arrow-right"></span></button>
        </div>
      </div>
    </div>
  </form>
</#if>

</@layout.registrationLayout>
<script>
  cacDn = document.getElementById("certificate_subjectDN");
  cacDn.innerHTML = cacDn.innerHTML.split(", ").join("<br />");
  cacDn.innerHTML = cacDn.innerHTML.split("CN=").join("<br />CN=");
</script>
