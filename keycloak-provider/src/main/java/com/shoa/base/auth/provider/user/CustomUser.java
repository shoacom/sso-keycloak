package com.shoa.base.auth.provider.user;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.LegacyUserCredentialManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.List;
import java.util.Map;


class CustomUser extends AbstractUserAdapter {

    private final String username;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final String avatar;
    private final String userId;

    private CustomUser(KeycloakSession session, RealmModel realm,
                       ComponentModel storageProviderModel,
                       String username,
                       String email,
                       String firstName,
                       String lastName,
                       String avatar,
                       String userId) {
        super(session, realm, storageProviderModel);
        this.username = username;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.avatar = avatar;
        this.userId = userId;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getFirstName() {
        return firstName;
    }

    @Override
    public String getLastName() {
        return lastName;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new LegacyUserCredentialManager(session, realm, this);
    }


    public String getAvatar() {
        return avatar;
    }

    public String getUserId() {
        return userId;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, getUsername());
        attributes.add(UserModel.EMAIL, getEmail());
        attributes.add(UserModel.FIRST_NAME, getFirstName());
        attributes.add(UserModel.LAST_NAME, getLastName());
        attributes.add("avatar", getAvatar());
        attributes.add("userId", getUserId());
        return attributes;
    }

    static class Builder {
        private final KeycloakSession session;
        private final RealmModel realm;
        private final ComponentModel storageProviderModel;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
        private String avatar;
        private String userId;

        Builder(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel, String username) {
            this.session = session;
            this.realm = realm;
            this.storageProviderModel = storageProviderModel;
            this.username = username;
        }

        Builder email(String email) {
            this.email = email;
            return this;
        }

        Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }

        Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }

        Builder avatar(String avatar) {
            this.avatar = avatar;
            return this;
        }

        Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        CustomUser build() {
            return new CustomUser(
                    session,
                    realm,
                    storageProviderModel,
                    username,
                    email,
                    firstName,
                    lastName,
                    avatar,
                    userId);

        }
    }
}