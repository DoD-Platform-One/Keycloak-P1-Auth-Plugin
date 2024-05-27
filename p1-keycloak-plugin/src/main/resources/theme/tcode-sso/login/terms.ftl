<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "form">
        <div id="kc-terms-text" onclick="javascript:document.getElementById('kc-accept').focus()">
            <div>
                <div class="alert alert-info cac-info">
                    <span>Click anywhere on the terms below to move to [accept] and [cancel] actions.</span>
                </div>
                <h4>You are accessing a U.S. Government (USG) Information System (IS) that is provided for
                    USG-authorized use only.</h4>
                <h5>By using this IS (which includes any device attached to this IS), you consent to the following
                    conditions:</h5>
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
                    <li>Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative
                           searching or monitoring of the content of privileged communications, or work product, related to
                           personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.
                           Such communications and work product are private and confidential. See <a class="linkInline"
                           href="https://www.my.af.mil/afp/netstorage/login_page_files_cloud_one/dod-user-agreement.html"
                           target="_blank">User Agreement</a> for details.
                    </li>
                    <li>Internet / Intranet / Extranet-related systems, including but not limited to computer equipment, software,
                           operating systems, storage media, and network accounts providing electronic mail, Internet browsing, and
                           file transfer protocol (FTP) capability that are owned or managed by Platform One are the property of Platform One.
                           These systems are to be used for organizational purposes in serving the interests of Platform One, and of our clients
                           and customers in the course of normal operations.
                    </li>
                    <li>Accessing data, a server or an account for any purpose other than conducting Platform One business, even if you have
                           authorized access, is prohibited. Revealing or sharing your account password, CAC credentials, or other MFA information,
                           methods, and codes to others or allowing use of your account by others is strictly prohibited.
                    </li>
                    <li>There is the potential that information presented and exported from the Platform One contains Controlled Unclassified
                           Information (CUI). It is the responsibility of all users to ensure information extracted from Platform One is appropriately
                           marked and properly safeguarded. If you are not sure of the safeguards necessary for the information, contact your functional
                           lead or Information Security Officer.
                    </li>
                </ul>
            </div>
        </div>
        <hr>
        <form class="form-actions text-right" action="${url.loginAction}" method="POST">
            <input class="btn btn-primary"
                   name="accept" id="kc-accept" type="submit" value="${msg("doAccept")}"/>
            <input class="btn btn-light"
                   name="cancel" id="kc-decline" type="submit" value="${msg("doDecline")}"/>
        </form>
        <div class="clearfix"></div>
    </#if>
</@layout.registrationLayout>
