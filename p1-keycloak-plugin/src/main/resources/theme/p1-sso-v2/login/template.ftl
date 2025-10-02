<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false showAnotherWayIfPresent=true useCardLayout=true>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" class="${properties.kcHtmlClass!}">

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="robots" content="noindex, nofollow">

    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
    <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />
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

<body class="${properties.kcBodyClass!}">
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
          </div>
          <div class="header-angle right">
            <img class="v-img__img v-img__img--contain" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACUAAABFCAYAAADNai9ZAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAEySURBVHgB7dnLTcNAFIXhew20gYAOKCUlpANKIB2QTighJWSJBETXHaSBPMaRLF3leWLPa3G+5ax+nY09Gn1+e9lJZRqpEKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQjEIxCsUoFKNQVUWpyLpRmTxKJVTlWzcyNbN18ahunfCMNmv/7as/KxoV1lnok0zbHzN/XiTq3Dpe9qhL63jZom6t42WJQtbxkkbds46XLOredbzoUUPX8aJGhaClPoR1fm0pI8SMmrUr+5QIRkf169jIdbyxUfOwzodENigqrGPahHX+bCEJDPmfmutW3lMFdeClUq/joUslX8e7ulTOdbxrS2VdxztZqtQ63vFSxdbxDkt1H9GwzqR0TK85XG228lpLUGcPPQh44t99Sr4AAAAASUVORK5CYII=" alt="">
          </div>
        </div>
      </header>
    <#if useCardLayout>
        <#if useCardLayout>
            <div class="container-fluid">
                <div class="row justify-content-center">
                    <div class="col-xl-6 col-lg-8 col-md-12">
                        <div class="card">
                            <div class="card-body">
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
                        </div>
                    </div>
                </div>
            </div>
        <#else>
            <#nested "form">
        </#if>
    <#else>
        <#nested "form">
    </#if>

    <#include "footer.ftl" />
</body>
</html>
</#macro>
