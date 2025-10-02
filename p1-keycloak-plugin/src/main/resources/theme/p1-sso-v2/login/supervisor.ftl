<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
<#if section = "form">
  <div id="kc-faq-content">
    <h1>Onboarding Supervisors</h1>

    <div class="faq-item">
      <h3 class="faq-title">What is an Onboarding Supervisor?</h3>
      <div class="faq-answer active">
        <p>The designated onboarding supervisor is responsible for onboarding and offboarding members of their team. This includes submitting access requests, adding users to their collaboration tool and Gitlab spaces, keeping track of license allocations and submitting help desk ticket on behalf of your team.
        </p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I am an Onboarding Supervisor, what do I do now?</h3>
      <div class="faq-answer">
        <p>The main responsibility of the onboarding supervisor is to make sure team members can access the applications and tools needed to work. Use the link below to submit access requests for your members:
        <p><a href="https://jira.il2.dso.mil/servicedesk/customer/portal/1/user/login?destination=portal%2F1%2Fcreate%2F498">Application Access Form</a></p>
        </p>
        <p>If you are a Mattermost Only onboarding supervisor, use the link below to submit access requests for your members:
        <p><a href="https://jira.il2.dso.mil/servicedesk/customer/portal/1/user/login?destination=portal%2F1%2Fcreate%2F700">Mattermost License Request Form</a></p>
        </p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I've submitted access requests for my members but I cannot add them to our team spaces, what do I do?</h3>
      <div class="faq-answer">
        <p>If you submitted your member's access request and it was granted, make sure the user has logged into the application or tool they need initially so their account can be populated into the Keycloak system. Once they login once, their account can be added to the tools they need.</p>
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I need to add another Onboarding Supervisor to my team, how do I do that?</h3>
      <div class="faq-answer">
        <p>You can add and remove onboarding supervisors by submitting the following ticket:
        <p><a href="https://jira.il2.dso.mil/servicedesk/customer/portal/1/user/login?destination=portal%2F1%2Fcreate%2F1086">Add/Remove Onboarding Supervisor Form<span class="icon ext append"></span></a></p>
        <p>Please note that this ticket can ONLY be filled out by existing onboarding supervisors on your team.
      </div>
    </div>

    <div class="faq-item">
      <h3 class="faq-title">I am an Onborading Supervisor, but when I fill out the access request form I get an error message. HELP!</h3>
      <div class="faq-answer">
        <p>If you receive and error message when filling out the application access form and you are the designated onboarding supervisor for your team, please email the Party Bus Onboarding team at:</p>
        <p><a href="mailto:aflcmc.hncx.p1-pbo@us.af.mil">aflcmc.hncx.p1-pbo@us.af.mil<span class="icon mail append"></span></a></p>
      </div>
    </div>

  </div>

    <div class="back-link">
      <a href="${url.loginUrl}" class="btn btn-primary outline">Return to Login</a>
    </div>
    
</#if>

<script>
  let acc = document.getElementsByClassName("faq-title");
  let i;

  for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener("click", function() {
    this.classList.toggle("active");
    let panel = this.nextElementSibling;
    if (panel.style.maxHeight) {
      panel.style.maxHeight = null;
    } else {
      panel.style.maxHeight = panel.scrollHeight + "px";
    }
  });
}
</script>
</@layout.registrationLayout>
