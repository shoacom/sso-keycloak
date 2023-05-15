package com.shoa.base.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Maps;
import org.keycloak.common.util.SystemEnvProperties;
import org.keycloak.services.util.JsonConfigProviderFactory;

import java.util.Map;
import java.util.Properties;

public class RegularJsonConfigProviderFactory extends JsonConfigProviderFactory {
    private KeycloakCustomProperties keycloakCustomProperties;

    public RegularJsonConfigProviderFactory(KeycloakCustomProperties keycloakCustomProperties) {
        this.keycloakCustomProperties = keycloakCustomProperties;
    }

    @Override
    protected Properties getProperties() {
        Map<String, String> overrides = Maps.newHashMap();
        Map<String, String> connectionsJpaMap = keycloakCustomProperties.getConnectionsJpa();
        connectionsJpaMap.forEach((k, v) -> overrides.put("keycloak.connectionsJpa." + k + ":", v));
        return new SystemEnvProperties(overrides);
    }

}
