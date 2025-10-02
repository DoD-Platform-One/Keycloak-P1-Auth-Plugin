# Client-Specific Login Tracking

This document describes how to use the Client-Specific Login Tracking feature in the P1 Keycloak Plugin.

## Overview

The Client-Specific Login Tracking feature allows you to track user login events for specific Keycloak clients and store the timestamp in user attributes. This is useful for tracking when users last logged into specific applications or groups of applications.

Unlike the standard LastLogin feature which tracks all login events regardless of client, this feature allows you to:

1. Define multiple login tracking attributes
2. Associate each attribute with a specific set of clients
3. Only update the attribute when a user logs into one of the associated clients

## Configuration

The feature is configured through the YAML configuration file, the same one used for other P1 Keycloak Plugin features.

### Example Configuration

Add a `clientLoginAttributes` section to your YAML configuration file:

```yaml
# Client-specific login attributes
clientLoginAttributes:
  - attributeName: "ABCGroupLastLogin"
    description: "Last login timestamp for ABC group applications"
    clientIds:
      - "abc-client"
      - "abc-admin"
      - "abc-mobile"
  
  - attributeName: "DEFGroupLastLogin"
    description: "Last login timestamp for DEF group applications"
    clientIds:
      - "def-client"
      - "def-admin"
      - "def-portal"
```

### Configuration Properties

Each entry in the `clientLoginAttributes` list has the following properties:

- `attributeName`: The name of the user attribute that will store the login timestamp
- `description`: (Optional) A description of this configuration entry
- `clientIds`: A list of Keycloak client IDs that should trigger updates to this attribute

## How It Works

When a user logs in:

1. The system checks which client the user logged into
2. It looks through all the configured `clientLoginAttributes` entries
3. If the client ID matches any in the `clientIds` list, it:
   - Stores the current timestamp in the specified attribute
   - If the attribute already had a value, it moves the old value to a "prior" attribute (e.g., `priorABCGroupLastLogin`)

## Timestamp Format

The timestamp is stored in ISO-8601 format with UTC timezone, for example: `2023-04-15T14:32:09.123Z`

## Enabling the Feature

The feature is implemented as an event listener. To enable it:

1. Make sure your YAML configuration file includes the `clientLoginAttributes` section
2. Add the event listener to your Keycloak configuration:

```
kc.sh start --spi-events-listener-ClientSpecificLogin-enabled=true
```

Or add it to your `standalone.xml` or `standalone-ha.xml` configuration:

```xml
<spi name="eventsListener">
    <provider name="ClientSpecificLogin" enabled="true">
    </provider>
</spi>
```

## Accessing the Data

The login timestamps are stored as user attributes and can be accessed through:

- The Keycloak Admin Console (Users → Attributes)
- The Keycloak REST API
- Custom code using the Keycloak SPI

## Use Cases

- Track when users last accessed specific applications
- Implement application-specific inactivity policies
- Generate reports on application usage patterns
- Trigger workflows based on application-specific login events