// mm_username.js — Nashorn-compatible (Keycloak 26.3.4+)
//
// NOTE:
//   This script runs inside Keycloak’s embedded Nashorn JS engine.
//   Nashorn is ES5-oriented and does NOT support two modern JS features
//   that SonarQube flags by default:
//
//   1. `let` / `const` → not supported by Nashorn (use `var` instead).
//      SonarQube rule: javascript:S3504
//
//   2. Optional chaining (`?.`) → not supported by Nashorn (must use
//      explicit null-checks like `if (attrs != null && attrs.containsKey(...))`).
//      SonarQube rule: javascript:S6582
//
// These two rules are therefore suppressed in `sonar-project-dev.properties`
// (see sonar.issue.ignore.multicriteria.e1/e2) specifically for this file.
// This is deliberate and safe — no functional or security impact.
//
// Logic summary:
//   - Default username is Keycloak’s user.getUsername().
//   - If user attribute "mm_username" exists, use that instead.
//   - Else if attribute "mm_use_email" is true, fallback to the email local-part.
//   - Otherwise, fallback to original username.
//   - Always export a non-empty string.

try {
  var uname = String(user.getUsername());
  var out   = uname;
  var attrs = user.getAttributes();

  // explicit override (as-is)
  if (attrs != null && attrs.containsKey("mm_username")) {
    var vv = attrs.get("mm_username");
    if (vv && !vv.isEmpty() && vv.get(0) != null) {
      out = String(vv.get(0));
    }
  } else if (attrs != null && attrs.containsKey("mm_use_email")) {
    // flagged subset: email local-part (as-is)
    var ff = attrs.get("mm_use_email");
    var on = ff && !ff.isEmpty() && ff.get(0) != null &&
             String(ff.get(0)).toLowerCase() === "true";
    if (on) {
      var email = user.getEmail();
      if (email != null) {
        email = String(email);
        var at = email.indexOf("@");
        if (at > 0) {
          out = email.substring(0, at);
        }
      }
    }
  }

  if (out == null || String(out).trim().length === 0) {
    out = uname;
  }

  exports = String(out);
} catch (e) {
  // defensive fallback on any failure
  exports = String(user.getUsername());
}
