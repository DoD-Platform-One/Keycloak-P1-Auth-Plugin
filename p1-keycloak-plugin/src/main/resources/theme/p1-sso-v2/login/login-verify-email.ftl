<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
<#-- We want to control the main title with H1, so suppress the default message box from template.ftl -->
<#if section = "header">
  <#-- Step Counter -->
  <#-- Assumes your existing CSS for .step-counter handles the airplane image based on active step -->
  <div>
    <ul class="step-counter">
      <li class="step step-1 active">
        <span class="sr-only">Step&nbsp;</span>
        <span>1</span>
        <span class="sr-only">&nbsp;of 5</span>
      </li>
      <li class="step step-2 active">
        <span class="sr-only">Step&nbsp;</span>
        <span>2</span>
        <span class="sr-only">&nbsp;of 5</span>
      </li>
      <li class="step step-3 current active">
        <span class="sr-only">Step&nbsp;</span>
        <span>3</span>
        <span class="sr-only">&nbsp;of 5</span>
      </li>
      <li class="step step-4">
        <span class="sr-only">Step&nbsp;</span>
        <span>4</span>
        <span class="sr-only">&nbsp;of 5</span>
      </li>
    </ul>
  </div>
  </div>
<#elseif section="form">
  <div id="kc-form-wrapper" class="${properties.kcFormAreaWrapperClass!}">
    <h1 id="kc-page-title">${msg("verifyEmailStepTitle")}</h1>
    <p>${msg("verifyEmailHoorayMessage")}</p>
    <p>${msg("verifyEmailInstructions")}</p>
    <p>${msg("verifyEmailCloseWindowMessage")}</p>
    <h2>${msg("verifyEmailDidntReceiveTitle")}</h2>
    <p>I'm sure you did, but please double check your SPAM folder.</p>
    <form action="${url.loginAction}" method="post">
      <a href="${url.loginAction}" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" role="button">
        ${msg("verifyEmailResendButton")}
      </a>
    </form>
  </div>
</#if>
</@layout.registrationLayout>
