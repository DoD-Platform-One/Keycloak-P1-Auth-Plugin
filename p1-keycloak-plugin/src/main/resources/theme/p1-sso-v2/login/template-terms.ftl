<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false showAnotherWayIfPresent=true>
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
  <html xmlns="http://www.w3.org/1999/xhtml" class="${properties.kcHtmlClass!}">

    <head>
      <meta charset="utf-8">
      <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
      <meta name="robots" content="noindex, nofollow">
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
          <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
      </#if>
      <title>${msg("loginTitle",(realm.displayName!''))}</title>
      <link rel="icon" href="${url.resourcesPath}/img/favicon.svg" />
      <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
          <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
      </#if>
      <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
          <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
      </#if>
      <#if scripts??>
        <#list scripts as script>
          <script src="${script}" type="text/javascript"></script>
        </#list>
      </#if>
    </head>

    <body class="${properties.kcBodyClass!} term-page">
      <header>
        <div class="banner">
          UNCLASSIFIED (IL2)
        </div>
        <div class="header-wrapper">
          <div class="header-angle left">
            <img class="v-img__img v-img__img--contain" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACUAAABFCAYAAADNai9ZAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEySURBVHgB7dnLTcNAFIXhew20gYAOKCUlpANKIB2QTighJWSJBETXHaSBPMaRLF3leWLPa3G+5ax+nY09Gn1+e9lJZRqpEKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQVUWpyLpRmTxKJVTlWzcyNbN18ahunfCMNmv/7as/KxoV1lnok0zbHzN/XiTq3Dpe9qhL63jZom6t42WJQtbxkkbds46XLOredbzoUUPX8aJGhaClPoR1fm0pI8SMmrUr+5QIRkf169jIdbyxUfOwzodENigqrGPahHX+bCEJDPmfmutW3lMFdeClUq/joUslX8e7ulTOdbxrS2VdxztZqtQ63vFSxdbxDkt1H9GwzqR0TK85XG228lpLUGcPPQh44t99Sr4AAAAASUVORK5CYII=" alt="">
          </div>
          <div class="header-content">
            <div class="logo-container">
              <a href="https://p1.dso.mil" target="_blank" class="logo-container">
                <img src="${url.resourcesPath}/img/p1-logo-new.svg" alt="Platform One Logo" class="p1-logo-img lg">
                <img src="${url.resourcesPath}/img/p1-logo-icon.svg" alt="Platform One Logo" class="p1-logo-img sm">
              </a>
            </div>
            <#if client?? && (client.name?has_content || client.clientId?has_content)>
              <div class="client-info">
                <h2 class="client-unique-name">
                  <#if client.name?has_content>
                    ${client.name?no_esc}
                  <#else>
                    ${client.clientId?no_esc}
                  </#if>
                </h2>
              </div>
            </#if>
          </div>
          <div class="header-angle right">
            <img class="v-img__img v-img__img--contain" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACUAAABFCAYAAADNai9ZAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEySURBVHgB7dnLTcNAFIXhew20gYAOKCUlpANKIB2QTighJWSJBETXHaSBPMaRLF3leWLPa3G+5ax+nY09Gn1+e9lJZRqpEKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQVUWpyLpRmTxKJVTlWzcyNbN18ahunfCMNmv/7as/KxoV1lnok0zbHzN/XiTq3Dpe9qhL63jZom6t42WJQtbxkkbds46XLOredbzoUUPX8aJGhaClPoR1fm0pI8SMmrUr+5QIRkf169jIdbyxUfOwzodENigqrGPahHX+bCEJDPmfmutW3lMFdeClUq/joUslX8e7ulTOdbxrS2VdxztZqtQ63vFSxdbxDkt1H9GwzqR0TK85XG228lpLUGcPPQh44t99Sr4AAAAASUVORK5CYII=" alt="">
          </div>
        </div>
      </header>

      <main class="main-content page-two-col">
        <#--
        <div class="card-header">
          <div class="p-0">
            <#if client?? && client.description?has_content>
              <img src="${client.description}"/>
            <#else>
              <img src="${url.resourcesPath}/img/p1-logo.png"/>
            </#if>
          </div>
          -->
          <div class="my-auto" style="display: none;">
            <#if client?? && client.name?has_content>
              <h2 class="client-unique-name">${client.name}</h2>
            <#else>
              <h2>${kcSanitize(msg("loginTitleHtml",(realm.displayNameHtml!'')))?no_esc}</h2>
            </#if>
          </div>
        </div>
        <section class="content login max-xl mx-auto flex"> 
          <div class="container terms">
            <div id="kc-terms-text" >
              <h2>Terms & Conditions</h2>
              <div class="terms-body">
                <p>
                You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
                </p>
                <p>
                By using this IS (which includes any device attached to this IS), you consent to the following conditions:
                </p>
                <ul>
                  <li>The USG routinely intercepts and monitors communications on this IS for purposes including, but
                    not limited to, penetration testing, COMSEC monitoring, network operations and defense,
                    personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
                  </li>
                  <li>At any time, the USG may inspect and seize data stored on this IS.</li>
                  <li>Communications using, or data stored on, this IS are not private, are subject to routine
                    monitoring, interception, and search, and may be disclosed or used for any USG authorized
                    purpose.
                  </li>
                  <li>This IS includes security measures (e.g., authentication and access controls) to protect USG
                    interests--not for your personal benefit or privacy.
                  </li>
                  <li>NOTICE: There is the potential that information presented and exported from the Platform One
                    contains FOUO or Controlled Unclassified Information (CUI). It is the responsibility of all
                    users to ensure information extracted from Platform One is appropriately marked and properly
                    safeguarded. If you are not sure of the safeguards necessary for the information, contact your
                    functional lead or Information Security Officer.
                  </li>
                  <li>Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI
                    investigative searching or monitoring of the content of privileged communications, or work
                    product, related to personal representation or services by attorneys, psychotherapists, or
                    clergy, and their assistants. Such communications and work product are private and confidential.
                    See <a class="linkInline"
                      href="https://www.my.af.mil/afp/netstorage/login_page_files_cloud_one/dod-user-agreement.html"
                      target="_blank">User Agreement</a> for details.
                  </li>
                </ul>
              </div>
            </div>
          </div>

          <div class="container login-form flex flex-col mx-auto">
            <#-- App-initiated actions should not see warning messages about the need to complete the action -->
            <#-- during login.                                                                               -->
            <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
              <div id="alert-error" class="error-messages alert alert-${message.type} ${properties.kcAlertClass!} alert-<#if message.type = 'error'>danger<#else>${message.type}</#if>">
                <span class="${properties.kcAlertTitleClass!}">${kcSanitize(message.summary)?no_esc}</span>
              </div>
            </#if>

            <#nested "form">

              <#if displayInfo>
                <div id="kc-info" class="${properties.kcSignUpClass!}">
                  <div id="kc-info-wrapper">
                    <#nested "info">
                      </div>
                </div>
              </#if>
          </div>
        </section>
      </main>

      <#include "footer.ftl" />
    </body>
  </html>
</#macro>
