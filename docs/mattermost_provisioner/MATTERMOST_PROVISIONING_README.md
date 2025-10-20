# Mattermost User Provisioning for Keycloak

## Overview

This implementation provides automatic user provisioning from Keycloak to Mattermost based on user personas. When a user registers in Keycloak with a persona attribute, they are automatically provisioned into Mattermost. The Mattermost plugin handles the persona-to-team/channel mappings internally via its own Jira lookups.

## Architecture

### Components

1. **MattermostProvisioningEventListenerProvider** - Main event listener that handles user registration events
2. **MattermostProvisioningEventListenerProviderFactory** - Factory for creating the event listener
3. **YAMLConfigMattermostProvisioning** - Configuration model for YAML-based configuration
4. **CommonConfig** - Handles YAML loading with environment variable substitution

### Flow

1. User registers in Keycloak with a `persona` attribute (e.g., `123-ORG-role`)
2. Event listener captures VERIFY_EMAIL event (ensures email is validated)
3. For each enabled environment (TEST, IL2, IL4, IL5):
   - Sends user data and persona to Mattermost provisioning endpoint
   - Mattermost plugin handles Jira lookups internally
4. Marks user as provisioned with list of successful environments

## Configuration

### YAML Configuration Structure

The plugin is configured via the `customreg.yaml` file:

```yaml
mattermostProvisioning:
  enabled: true
  requestTimeoutSeconds: 30
  environments:
    TEST:
      enabled: true
      provisionUrl: "https://chat.test.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_TEST_PROVISION_TOKEN}"
    IL2:
      enabled: true
      provisionUrl: "https://chat.il2.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL2_PROVISION_TOKEN}"
    IL4:
      enabled: true
      provisionUrl: "https://chat.il4.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL4_PROVISION_TOKEN}"
    IL5:
      enabled: false
      provisionUrl: "https://chat.il5.dso.mil/plugins/auto-provision/provision"
      provisionToken: "${MATTERMOST_IL5_PROVISION_TOKEN}"
```

### Environment Variables

The system provisions users in ALL enabled environments from a single Keycloak instance:

- `MATTERMOST_TEST_PROVISION_TOKEN` - Token for TEST Mattermost
- `MATTERMOST_IL2_PROVISION_TOKEN` - Token for IL2 Mattermost
- `MATTERMOST_IL4_PROVISION_TOKEN` - Token for IL4 Mattermost
- `MATTERMOST_IL5_PROVISION_TOKEN` - Token for IL5 Mattermost
- `CUSTOM_REGISTRATION_CONFIG` - Path to YAML configuration file

### Kubernetes Deployment

1. **Create Secrets** for sensitive data:

```bash
kubectl create secret generic mattermost-provisioning-secrets \
  --from-literal=test-token="pvt_xxx" \
  --from-literal=il2-token="pvt_xxx" \
  --from-literal=il4-token="pvt_xxx" \
  --from-literal=il5-token="pvt_xxx"
```

2. **Create ConfigMap** with customreg.yaml configuration
3. **Update Helm values** to mount config and set environment variables

## User Attributes

### Required Attributes

- **persona**: Format `<ticket>-<customer>-<personaKey>`
  - Example: `123-ORG-role`
  - `123` maps to Jira ticket `CTT-123`
  - `ORG` is the customer identifier
  - `role` is the persona key

### Tracking Attributes

The system automatically sets these attributes on successful provisioning:

- **mattermost_provisioned**: Set to "true" when provisioned in at least one environment
- **mattermost_provisioned_environments**: Comma-separated list of successful environments (e.g., "TEST,IL2,IL4")
- **mattermost_provisioned_failed**: Comma-separated list of failed environments (if any)
- **mattermost_provisioned_date**: Unix timestamp of provisioning

## Mattermost Plugin Configuration

The Mattermost Auto-Provisioning Plugin handles all Jira lookups internally. It will:
1. Parse the persona to extract the ticket number
2. Query Jira for the persona-to-team/channel mappings
3. Provision the user into appropriate teams and channels

No Jira configuration is needed in Keycloak - this is all handled by Mattermost.

## User Profile Configuration

**IMPORTANT**: Before users can enter persona values during registration, you must configure the User Profile attribute.

### Add Persona Attribute to User Profile

1. Log in to Keycloak Admin Console
2. Select your realm
3. Navigate to **Realm Settings** → **User Profile** → **Attributes**
4. Click **"Create Attribute"**
5. Configure the attribute:
   - **Name**: `persona`
   - **Display name**: `Mattermost Access Code`
   - **Description**: `Optional code for Mattermost team provisioning`
   - **Multivalued**: `Off` (single-valued)
   - **Required**: `Off` (optional field)
   - **Attribute Group**: `user-metadata`
   - **Permissions**:
     - **Who can edit**: User, Admin
     - **Who can view**: User, Admin
6. Click **"Save"**

**Note**: Without this User Profile configuration, the persona field will appear in the registration form but the value will not be saved to the user attributes.

## Enabling the Event Listener

### Via Keycloak Admin Console

1. Log in to Keycloak Admin Console
2. Select your realm
3. Navigate to **Events** → **Config**
4. In the **Event Listeners** field, add: `mattermost-provisioning`
5. Save the configuration

### Via Keycloak CLI

```bash
kcadm.sh update events/config -r <realm> \
  -s "eventsListeners=[\"mattermost-provisioning\",\"jboss-logging\"]"
```

## Testing

### 1. Create Test User with Persona

```bash
# Using Keycloak Admin API
curl -X POST "https://keycloak.example.mil/auth/admin/realms/myrealm/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "username": "test.user",
    "email": "test.user@example.mil",
    "firstName": "Test",
    "lastName": "User",
    "enabled": true,
    "attributes": {
      "persona": ["123-ORG-role"]
    }
  }'
```

### 2. Verify Provisioning

Check Keycloak logs:
```bash
kubectl logs -f keycloak-pod | grep MattermostProvisioning
```

Check user attributes:
```bash
kcadm.sh get users/<user-id> -r <realm> | jq '.attributes'
```

### 3. Test Mattermost Endpoint Directly

```bash
curl -X POST "https://chat.il4.dso.mil/plugins/auto-provision/provision" \
  -H "Content-Type: application/json" \
  -H "X-Provision-Token: pvt_xxx" \
  -H "Idempotency-Key: $(uuidgen)" \
  --data '{
    "username": "test.user",
    "mattermostId": "keycloak-user-id",
    "firstName": "Test",
    "lastName": "User",
    "email": "test.user@example.mil",
    "persona": "123-ORG-role"
  }'
```

## Monitoring

### Log Patterns

Success:
```
INFO  [MattermostProvisioningEventListenerProvider] Provisioning user in Mattermost: test.user with persona: 123-ORG-role
INFO  [MattermostProvisioningEventListenerProvider] Successfully provisioned user in Mattermost: test.user
```

Errors:
```
ERROR [MattermostProvisioningEventListenerProvider] Error provisioning user in Mattermost
WARN  [MattermostProvisioningEventListenerProvider] Persona or IL mapping issue: <details>
```

### Metrics to Track

- Number of users provisioned per day
- Failed provisioning attempts
- Jira API response times (cached vs fresh)
- Mattermost API response times

## Troubleshooting

### Common Issues

1. **User not provisioned**
   - Check if `persona` attribute is set
   - Verify event listener is enabled in realm
   - Check if `mattermostProvisioning.enabled` is true in YAML

2. **422 errors from Mattermost**
   - Persona lacks mapping in Mattermost's Jira
   - Contact Mattermost admin to verify persona mappings

3. **404 errors from Mattermost**
   - Provisioning endpoint URL may be incorrect
   - Verify Mattermost plugin is installed and enabled

4. **401 errors from Mattermost**
   - Provisioning token is invalid or expired
   - Token not properly set in environment variables

5. **Connection timeouts**
   - Check network connectivity between Keycloak and Mattermost/Jira
   - Increase `requestTimeoutSeconds` if needed

## Security Considerations

1. **Credential Storage**
   - Use Kubernetes secrets for all credentials
   - Never commit credentials to version control
   - Rotate tokens regularly

2. **Network Security**
   - Ensure HTTPS is used for all connections
   - Consider network policies to restrict egress

3. **Audit Logging**
   - All provisioning attempts are logged
   - Monitor for suspicious patterns

4. **Rate Limiting**
   - The implementation includes caching to reduce Jira API calls
   - Consider implementing rate limiting if needed

## Future Enhancements

1. **Deprovisioning Support**
   - Handle user deletion/deactivation events
   - Remove users from Mattermost teams

2. **Group Updates**
   - Listen for group membership changes
   - Update Mattermost team memberships accordingly

3. **Bulk Provisioning**
   - Admin endpoint to provision existing users
   - Batch processing for efficiency

4. **Health Checks**
   - Endpoint to verify connectivity to Mattermost/Jira
   - Status dashboard for monitoring

## Support

For issues or questions:
1. Check Keycloak logs for detailed error messages
2. Verify configuration in customreg.yaml
3. Test endpoints independently with curl
4. Contact the Platform One team for assistance