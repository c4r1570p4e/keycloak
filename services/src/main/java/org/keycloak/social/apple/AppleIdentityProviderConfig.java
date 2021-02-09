package org.keycloak.social.apple;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * @author Emilien Bondu
 * @author Yang Xie
 */
public class AppleIdentityProviderConfig extends OIDCIdentityProviderConfig {

    private static final String TEAM_ID = "teamId";
    private static final String KEY_ID = "keyId";
    private static final String KEY = "key";

    public AppleIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public AppleIdentityProviderConfig() {
    }

    public String getTeamId() {
        return getConfig().get(TEAM_ID);
    }

    public void setTeamId(String teamId) {
        getConfig().put(TEAM_ID, teamId);
    }

    public String getKeyId() {
        return getConfig().get(KEY_ID);
    }

    public void setKeyId(String keyId) {
        getConfig().put(KEY_ID, keyId);
    }

    public String getKey() {
        return getConfig().get(KEY);
    }

    public void setKey(String key) {
        getConfig().put(KEY, key);
    }
}
