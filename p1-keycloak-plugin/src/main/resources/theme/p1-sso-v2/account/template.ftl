<#macro mainLayout active bodyClass>
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
  <html>
    <head>
      <meta charset="utf-8">
      <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
      <meta name="robots" content="noindex, nofollow">
      <meta name="viewport" content="width=device-width, initial-scale=1">

      <title>${msg("accountManagementTitle")}</title>
      <link rel="icon" href="${url.resourcesPath}/img/favicon.ico">
      <#if properties.stylesCommon?has_content>
        <#list properties.stylesCommon?split(' ') as style>
          <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
        </#list>
      </#if>
      <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
          <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
      </#if>
      <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
          <script type="text/javascript" src="${url.resourcesPath}/${script}"></script>
        </#list>
      </#if>
    </head>

    <body class="admin-console user ${bodyClass}">

      <header>
        <div class="banner">
          UNCLASSIFIED (IL2)
        </div>
        <div class="header-wrapper">
          <div class="header-angle left">
            <img class="v-img__img v-img__img--contain" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACUAAABFCAYAAADNai9ZAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEySURBVHgB7dnLTcNAFIXhew20gYAOKCUlpANKIB2QTighJWSJBETXHaSBPMaRLF3leWLPa3G+5ax+nY09Gn1+e9lJZRqpEKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQVUWpyLpRmTxKJVTlWzcyNbN18ahunfCMNmv/7as/KxoV1lnok0zbHzN/XiTq3Dpe9qhL63jZom6t42WJQtbxkkbds46XLOredbzoUUPX8aJGhaClPoR1fm0pI8SMmrUr+5QIRkf169jIdbyxUfOwzodENigqrGPahHX+bCEJDPmfmutW3lMFdeClUq/joUslX8e7ulTOdbxrS2VdxztZqtQ63vFSxdbxDkt1H9GwzqR0TK85XG228lpLUGcPPQh44t99Sr4AAAAASUVORK5CYII=" alt="">
          </div>
          <div class="header-content">
            <a href="https://p1.dso.mil" target="_blank" class="logo-container">
              <img src="${url.resourcesPath}/img/p1-logo-new.svg" alt="Platform One Logo" class="p1-logo-img lg">
              <img src="${url.resourcesPath}/img/p1-logo-icon.svg" alt="Platform One Logo" class="p1-logo-img sm">
            </a>

            <nav id="navbar" class="navbar navbar-expand-md fixed-top">
              <h3 class="sr-only"><a>${realm.displayName}</a></h3>
              <ul class="navbar-nav flex">
                <li class="nav-item <#if active=='applications'>active</#if>"><a class="nav-link" href="${url.applicationsUrl}">${msg("applications")}</a></li>
                <li class="nav-item <#if active=='account'>active</#if>"><a class="nav-link" href="${url.accountUrl}">${msg("account")}</a></li>
                <#if features.passwordUpdateSupported>
                  <li class="nav-item <#if active=='password'>active</#if>"><a class="nav-link" href="${url.passwordUrl}">${msg("password")}</a></li>
                </#if>
                <li class="nav-item <#if active=='totp'>active</#if>"><a class="nav-link" href="${url.totpUrl}">${msg("authenticator")}</a></li>
                  <#if features.identityFederation>
                <li class="nav-item <#if active=='social'>active</#if>"><a class="nav-link" href="${url.socialUrl}">${msg("federatedIdentity")}</a></li>
                </#if>
                <li class="nav-item <#if active=='sessions'>active</#if>"><a class="nav-link" href="${url.sessionsUrl}">Active ${msg("sessions")}</a></li>
                <li class="nav-item"><a class="nav-link" href="${url.logoutUrl}">${msg("doSignOut")}</a></li>
              </ul>
            </nav>

            <a id="hamburger" href="javascript:void(0);" class="fs-6">
              <i class="icon menu"></i>
            </a>

          </div>
          <div class="header-angle right">
            <img class="v-img__img v-img__img--contain" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACUAAABFCAYAAADNai9ZAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEySURBVHgB7dnLTcNAFIXhew20gYAOKCUlpANKIB2QTighJWSJBETXHaSBPMaRLF3leWLPa3G+5ax+nY09Gn1+e9lJZRqpEKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQVUWpyLpRmTxKJVTlWzcyNbN18ahunfCMNmv/7as/KxoV1lnok0zbHzN/XiTq3Dpe9qhL63jZom6t42WJQtbxkkbds46XLOredbzoUUPX8aJGhaClPoR1fm0pI8SMmrUr+5QIRkf169jIdbyxUfOwzodENigqrGPahHX+bCEJDPmfmutW3lMFdeClUq/joUslX8e7ulTOdbxrS2VdxztZqtQ63vFSxdbxDkt1H9GwzqR0TK85XG228lpLUGcPPQh44t99Sr4AAAAASUVORK5CYII=" alt="">
          </div>

        </div>
      </header>

      <main class="main-content page-one-col">
        <section class="content flex max-lg mx-auto">
          <div class="container">
            <div class="card">
              <div class="card-body">
                <#if message?has_content>
                  <div class="alert alert-${message.type}">
                    <#if message.type=='success' ><span class="pficon pficon-ok"></span></#if>
                    <#if message.type=='error' ><span class="pficon pficon-error-circle-o"></span></#if>
                    <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
                  </div>
                </#if>

                <#nested "content">

              </div>
            </div>
          </div>
        </section>
      </main>

      <#include "footer.ftl" />
    </body>
  </html>
</#macro>
