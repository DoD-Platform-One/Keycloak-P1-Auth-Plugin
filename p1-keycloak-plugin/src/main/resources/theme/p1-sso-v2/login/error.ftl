<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false useCardLayout=false; section>
<#if section = "form">
    <div class="container">
        <div class="flex flex-col justify-center" style="min-height: 25vh; text-align: center;">
            <div id="kc-error-message">
              <h1 id="kc-page-title" class="w-100">Something went wrong...</h1>
              <p class="subtitle">
                  <#if message?has_content>
                      ${message.summary}
                  <#else>
                      An unexpected error occurred. Please try again.
                  </#if>
              </p>
              <div class="mt-4">
                  <a href="${properties.kcHttpRelativePath!'/auth'}/realms/${realm.name}/account/applications" class="btn btn-primary">Back to Login</a>
              </div>
            </div>
        </div>
    </div>
</#if>
</@layout.registrationLayout>
