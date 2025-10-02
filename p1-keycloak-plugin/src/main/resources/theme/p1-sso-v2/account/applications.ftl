<#import "template.ftl" as layout>
<@layout.mainLayout active='applications' bodyClass='user'; section>
<span class="final-step f35"></span>
<h1>Welcome aboard Platform One!</h1>
<h2>Sign in to your applications.</h2>
<p>Note: you may not have access to all of these acounts. Make sure your Onboarding Supervisor has submitted an <a href="https://jira.il2.dso.mil/servicedesk/customer/portal/1/user/login?destination=portal%2F1%2Fcreate%2F498" target="_blank">application request</a> to get you access to all of your tools.</p>

<div class="table">
  <div class="table-row">
    <div class="table-label">ChatOps</div>
    <div class="table-value" id="name">
      <a href="https://chat.il2.dso.mil" target="_blank" class="btn btn-xs text primary">chat.il2.dso.mil</a>
      <a href="https://chat.il4.dso.mil" target="_blank" class="btn btn-xs text primary">chat.il4.dso.mil</a>
      <a href="https://chat.il5.dso.mil" target="_blank" class="btn btn-xs text primary">chat.il5.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Confluence</div>
    <div class="table-value" id="organization">
      <a href="https://confluence.il2.dso.mil" target="_blank" class="btn btn-xs text primary">confluence.il2.dso.mil</a>
      <a href="https://confluence.il4.dso.mil" target="_blank" class="btn btn-xs text primary">confluence.il4.dso.mil</a>
      <a href="https://confluence.il5.dso.mil" target="_blank" class="btn btn-xs text primary">confluence.il5.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Jira</div>
    <div class="table-value" id="username">
      <a href="https://jira.il2.dso.mil" target="_blank" class="btn btn-xs text primary">jira.il2.dso.mil</a>
      <a href="https://jira.il4.dso.mil" target="_blank" class="btn btn-xs text primary">jira.il4.dso.mil</a>
      <a href="https://jira.il5.dso.mil" target="_blank" class="btn btn-xs text primary">jira.il5.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Code</div>
    <div class="table-value" id="username">
      <a href="https://code.il2.dso.mil" target="_blank" class="btn btn-xs text primary">code.il2.dso.mil</a>
      <a href="https://code.il4.dso.mil" target="_blank" class="btn btn-xs text primary">code.il4.dso.mil</a>
      <a href="https://code.il5.dso.mil" target="_blank" class="btn btn-xs text primary">code.il5.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Parabol</div>
    <div class="table-value" id="username">
      <a href="https://parabol.il2.dso.mil" target="_blank" class="btn btn-xs text primary">parabol.il2.dso.mil</a>
      <a href="https://parabol.il4.dso.mil" target="_blank" class="btn btn-xs text primary">parabol.il4.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Repo 1</div>
    <div class="table-value" id="username">
      <a href="https://repo1.dso.mil" target="_blank" class="btn btn-xs text primary">repo1.dso.mil</a>
    </div>
  </div>

  <div class="table-row">
    <div class="table-label">Resource Center</div>
    <div class="table-value" id="username">
      <div class="flex gap-3 align-items-center flex-wrap">
        <a href="https://p1.dso.mil/resources" target="_blank" class="btn btn-xs text primary btn-xs outline">Discover best practices, docs and how-to content to accelerate your mission</a>
      </div>
    </div>
  </div>

</div>

<h2>Need help?</h2>
<div class="flex gap-3 align-items-center">
    <a href="https://jira.il2.dso.mil/servicedesk/customer/portal/1" target="_blank" class="btn btn-primary"><span class="icon prepend lock"></span>Support & Helpdesk<span class="icon append ext"></span></a>
    <a href="${properties.kcHttpRelativePath!'/auth'}/realms/${realm.name}/onboarding/faq" class="btn btn-primary outline">New account FAQ</a>
    <a href="https://forms.osi.apps.mil/pages/responsepage.aspx?id=jbExg4ct70ijX6yIGOv5tCs_tcEc7QxMu_7rPXEZOvtUNExXN1EwM0pUU1FXRlpQTlEyMVJSUUdFQi4u&route=shorturl" target="_blank" class="btn btn-primary">Schedule a consultation <span class="icon append ext"></span></a>
</div>
<p>If you ever lose access to IL2+ environments (e.g. locked out of your account), you may email: <br><a href="mailto:${msg("helpEmail")}">${msg("helpEmail")}</a></p>
<p>From all of us, thank you for trusting P1 to be your mission partners.</p>
</@layout.mainLayout>
