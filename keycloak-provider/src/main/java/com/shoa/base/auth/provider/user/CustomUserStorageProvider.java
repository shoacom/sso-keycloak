package com.shoa.base.auth.provider.user;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class CustomUserStorageProvider implements UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        UserQueryProvider {

    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    public static final String SQL_SELECT_ALL = "select username, nickname as firstName, null as lastName, email, avatar, uuid as userId";
    public static final String SQL_SELECT_PASSWORD = "select password";
    public static final String FROM_SQL_TABLE = " from sys_user";

    public static final String SQL_USER_BY_USERNAME = SQL_SELECT_ALL + FROM_SQL_TABLE + " where username = ?";
    public static final String SQL_USER_BY_EMAIL = SQL_SELECT_ALL + FROM_SQL_TABLE + " where email = ?";
    public static final String SQL_PASSWORD_BY_USER = SQL_SELECT_PASSWORD + FROM_SQL_TABLE + " where username = ?";
    public static final String SQL_USER_BY_PAGE = SQL_SELECT_ALL + FROM_SQL_TABLE + " order by username limit ? offset ?";
    public static final String SQL_USER_BY_USER_PAGE = SQL_SELECT_ALL + FROM_SQL_TABLE + " where username like ? order by username limit ? offset ?";

    private KeycloakSession ksession;
    private ComponentModel model;
    private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        log.info("[I35] getUserById({})", id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(realm, sid.getExternalId());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        log.info("[I41] getUserByUsername({})", username);
        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(SQL_USER_BY_USERNAME);
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if (rs.next()) {
                return mapUser(realm, rs);
            } else {
                return null;
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        log.info("[I48] getUserByEmail({})", email);
        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(SQL_USER_BY_EMAIL);
            st.setString(1, email);
            st.execute();
            ResultSet rs = st.getResultSet();
            if (rs.next()) {
                return mapUser(realm, rs);
            } else {
                return null;
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("[I57] supportsCredentialType({})", credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})", realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("[I57] isValid(realm={},user={},credentialInput.type={})", realm.getName(), user.getUsername(), credentialInput.getType());
        if (!this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();

        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(SQL_PASSWORD_BY_USER);
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if (rs.next()) {
                String pwd = rs.getString(1);
                return passwordEncoder.matches(credentialInput.getChallengeResponse(), pwd);
            } else {
                return false;
            }
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    // UserQueryProvider implementation

    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("[I93] getUsersCount: realm={}", realm.getName());
        try (Connection c = DbUtil.getConnection(this.model)) {
            Statement st = c.createStatement();
            st.execute("select count(*) from users");
            ResultSet rs = st.getResultSet();
            rs.next();
            return rs.getInt(1);
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, String s, Integer integer, Integer integer1) {
        return searchForUser(s, realmModel, integer, integer1).stream();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> map, Integer integer, Integer integer1) {
        return searchForUser(map, realmModel, integer, integer1).stream();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer integer, Integer integer1) {
        return Collections.EMPTY_LIST.stream();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String s, String s1) {
        return Collections.EMPTY_LIST.stream();
    }


    public List<UserModel> getUsers(RealmModel realm) {
        return getUsers(realm, 0, 5000); // Keep a reasonable maxResults
    }


    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        log.info("[I113] getUsers: realm={}", realm.getName());

        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(SQL_USER_BY_PAGE);
            st.setInt(1, maxResults);
            st.setInt(2, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while (rs.next()) {
                users.add(mapUser(realm, rs));
            }
            return users;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    public List<UserModel> searchForUser(String search, RealmModel realm) {
        return searchForUser(search, realm, 0, 5000);
    }

    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        log.info("[I139] searchForUser: realm={}", realm.getName());

        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement(SQL_USER_BY_USER_PAGE);
            st.setString(1, search);
            st.setInt(2, maxResults);
            st.setInt(3, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while (rs.next()) {
                users.add(mapUser(realm, rs));
            }
            return users;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return searchForUser(params, realm, 0, 5000);
    }


    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        return getUsers(realm, firstResult, maxResults);
    }


    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
        return new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
                .email(rs.getString("email"))
                .firstName(rs.getString("firstName"))
                .lastName(rs.getString("lastName"))
                .avatar(rs.getString("avatar"))
                .userId(rs.getString("userId"))
                .build();
    }


}
