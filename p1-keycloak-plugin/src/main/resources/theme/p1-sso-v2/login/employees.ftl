<#import "template-register.ftl" as layout>
<@layout.registrationLayout displayMessage=false>
<h1 class="text-center">Welcome to Platform One</h1>
<div class="message mx-auto">
  <div class="text-center">
    <h2>A Message From the Director</h2>
    <p>Congratulations on being selected for Platform One! We're excited to have you join us in our mission to provide the trusted foundation to continuously develop, secure, and operate better software. As part of this team, you'll play a key role in driving innovation and collaboration to power decisive warfighter advantage through software. Welcome aboard—we’re glad you’re here!</p>
    <p>— P1 Director of Operations</p>
  </div>

  <div class="text-center">
    <h2>Begin P1 Employee Onboarding</h2>
    <p>We have a different onboarding workflow for each personnel type.  Find your profile below to find the correct form for you.</p>
    <p>If you’re leaving Platform One, head down to our <a href="#offboarding">offboarding section</a>.</p>
  </div>
</div>

<div class="onboarding personnel-boxes flex text-center">
  <div class="personnel-box flex flex-col civilian text-center">
    <h3>Civilian Personnel</h3>
    <p>Government employees</p>
    <a class="btn btn-primary w-100" href="https://forms.osi.apps.mil/r/PsjxVtGsmU" target="_blank" rel="nofollow noreferrer">Civilian Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col military text-center">
    <h3>Military Personnel</h3>
    <p>Government employees</p>
    <a class="btn btn-primary w-100" href="https://forms.osi.apps.mil/r/F3B2fncSkq" target="_blank" rel="nofollow noreferrer">Military Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col epass text-center">
    <h3>A&AS Contractors (EPASS)</h3>
    <p>Advisory & Assistance Services contractors</p>
    <a class="btn btn-primary w-100" href="https://forms.osi.apps.mil/r/hNc4bmbnMm" target="_blank" rel="nofollow noreferrer">A&AS Contractor Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col p1-contractors text-center">
    <h3>P1 Contractors</h3>
    <p>All other Platform One Contractors</p>
    <a class="btn btn-primary w-100" href="https://forms.osi.apps.mil/r/BHhwztvjfb" target="_blank" rel="nofollow noreferrer">P1 Contractor Onboarding<span class="icon append ext"></span></a>
  </div>
</div>

<a class="btn btn-primary outline mx-auto" href="https://jira.il2.dso.mil/servicedesk/customer/portal/1">
  <span class="icon prepend lock" title="IL2 Access Req'd"></span>
  Visit our helpdesk
  <span class="icon append ext"></span>
</a>

<div class="message mx-auto mt-4">
  <div class="text-center">
    <h3>Not a P1 Employee?</h3>
    <p>Visit our <a href="TODO">Registration page</a> to create your free customer account.</p>
    <p>Access to Iron Bank and Big Bang IL2 is free. For more access, you’ll have to work with your onboarding supervisor or <a href="https://p1.dso.mil/contact-us">contact us to get started.<span class="icon append ext"></span></a></p>
  </div>
</div>

  <div class="table-table table-onboarding">
    <div class="table-row">
      <div class="table-label">Supporting Team</div>
      <div class="table-label">Team Function</div>
      <div class="table-label">Trusted Agent</div>
    </div>

    <div class="table-row">
      <div class="table-value">Party Bus</div>
      <div class="table-value">Fully managed DevSecOps service platform as a service (PaaS)</div>
      <div class="table-value">DJ Hines</div>
    </div>

    <div class="table-row">
      <div class="table-value">Big Bang</div>
      <div class="table-value">Open source DevSecOps platform.</div>
      <div class="table-value">Chris Williams</div>
    </div>

    <div class="table-row">
      <div class="table-value">Iron Bank</div>
      <div class="table-value">Vetted repository of assessed containers and images.</div>
      <div class="table-value">Capt Lee Lambert</div>
    </div>

    <div class="table-row">
      <div class="table-value">P1CE</div>
      <div class="table-value">Customer Experience, support, and training.</div>
      <div class="table-value">Natalie Burris</div>
    </div>

    <div class="table-row">
      <div class="table-value">Cyber</div>
      <div class="table-value">Security, compliance, and CTF.</div>
      <div class="table-value">Kelly Sunderland</div>
    </div>

    <div class="table-row">
      <div class="table-value">Cerberus</div>
      <div class="table-value">Enterprise services, infrastructure, and accounts.</div>
      <div class="table-value">Msgt Evan Inman</div>
    </div>

  </div>

<div id="offboarding" class="message mx-auto">
  <div class="text-center">
    <h2>Heading out?</h2>
    <p>We’re sad to see you go and wish you the best! Below we have our off boarding workflow for each personnel type.</p> 
  </div>
</div>

<div class="offboarding personnel-boxes flex text-center">
  <div class="personnel-box flex flex-col civilian text-center">
    <h3>Civilian Personnel</h3>
    <p>Government employees</p>
    <a class="btn btn-accent w-100" href="https://forms.osi.apps.mil/r/x3DB6djt2a" target="_blank" rel="nofollow noreferrer">Civilian Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col military text-center">
    <h3>Military Personnel</h3>
    <p>Government employees</p>
    <a class="btn btn-accent w-100" href="https://forms.osi.apps.mil/r/jJhwJDMhEj" target="_blank" rel="nofollow noreferrer">Military Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col epass text-center">
    <h3>A&AS Contractors (EPASS)</h3>
    <p>Advisory & Assistance Services contractors</p>
    <a class="btn btn-accent w-100" href="https://forms.osi.apps.mil/r/MCiuDPZVnM" target="_blank" rel="nofollow noreferrer">A&AS Contractor Onboarding<span class="icon append ext"></span></a>
  </div>

  <div class="personnel-box flex flex-col p1-contractors text-center">
    <h3>P1 Contractors</h3>
    <p>All other Platform One Contractors</p>
    <a class="btn btn-accent w-100" href="https://forms.osi.apps.mil/r/x8EaRadJPU" target="_blank" rel="nofollow noreferrer">P1 Contractor Onboarding<span class="icon append ext"></span></a>
  </div>

</div>
<a class="btn btn-primary outline mx-auto" href="https://jira.il2.dso.mil/servicedesk/customer/portal/1">
  <span class="icon prepend lock" title="IL2 Access Req'd"></span>
  Visit our helpdesk
  <span class="icon append ext"></span>
</a>
</@layout.registrationLayout>
