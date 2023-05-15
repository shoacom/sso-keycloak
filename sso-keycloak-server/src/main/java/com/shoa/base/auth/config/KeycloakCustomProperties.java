package com.shoa.base.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "keycloak.custom")
public class KeycloakCustomProperties {

    private Map<String, String> connectionsJpa;

    public Map<String, String> getConnectionsJpa() {
        return connectionsJpa;
    }

    public void setConnectionsJpa(Map<String, String> connectionsJpa) {
        this.connectionsJpa = connectionsJpa;
    }
}
