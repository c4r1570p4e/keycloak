/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.social.apple;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerECDSASignatureSignerContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.core.Response;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author Emilien Bondu
 * @author Yang Xie
 */
public class AppleIdentityProvider extends OIDCIdentityProvider implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(AppleIdentityProvider.class);

    public static final String AUTH_URL = "https://appleid.apple.com/auth/authorize?response_mode=form_post";
    public static final String TOKEN_URL = "https://appleid.apple.com/auth/token";
    public static final String ISSUER = "https://appleid.apple.com";
    public static final String DEFAULT_SCOPE = SCOPE_OPENID + " name email";
    protected static String userData;
    
    private static final String OIDC_PARAMETER_USER = "user";

    public AppleIdentityProvider(KeycloakSession session, AppleIdentityProviderConfig config) {
        super(session, config);

        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        logger.infof(config.getKey());
        logger.infof(config.getKeyId());
        logger.infof(config.getTeamId());
        if (!isValidSecret(config.getClientSecret())) {
            config.setClientSecret(generateClientSecret(config.getKey(), config.getKeyId(), config.getTeamId()));
        }
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    protected class OIDCEndpoint extends OIDCIdentityProvider.OIDCEndpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            super(callback, realm, event);
        }

        @POST
        public Response authResponse(@FormParam(OAUTH2_PARAMETER_STATE) String state,
            @FormParam(OAUTH2_PARAMETER_CODE) String authorizationCode,
            @FormParam(OIDC_PARAMETER_USER) String user,
            @FormParam(OAuth2Constants.ERROR) String error) {
            userData = user;
            return super.authResponse(state, authorizationCode, error);
        }
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext user = super.getFederatedIdentity(response);
        if (userData != null) {
            try {
                JsonNode userNode = asJsonNode(userData);
                if (userNode.has("email")) {
                    user.setEmail(getJsonProperty(userNode, "email"));
                }
                if (userNode.has("name")) {
                    JsonNode nameNode = userNode.get("name");
                    user.setFirstName(getJsonProperty(nameNode, "firstName"));
                    user.setLastName(getJsonProperty(nameNode, "lastName"));
                }
            } catch (Exception e) {
                throw new IdentityBrokerException("Failed to parse responded user data.", e);
            }
        }
        return user;
    }

    private String generateClientSecret(String pem, String keyId, String teamId) {
        try {
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setAlgorithm("ES256");
            keyWrapper.setPrivateKey(getPrivateKey(pem));
            return new JWSBuilder().kid(keyId).jsonContent(generateClientToken(teamId))
                .sign(new ServerECDSASignatureSignerContext(keyWrapper));
        } catch (Exception e) {
            throw new IdentityBrokerException("Failed to generate client secret.", e);
        }
    }
    
    private PrivateKey getPrivateKey(String pem) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("ECDSA");
        byte[] der = PemUtils.pemToDer(pem);
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(der);
        return kf.generatePrivate(keySpecPKCS8);
    }

    private boolean isValidSecret(String clientSecret) {
        if (clientSecret == null || clientSecret.isEmpty())
            return false;
        try {
            JWSInput jws = new JWSInput(clientSecret);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            return !token.isExpired();
        } catch (Exception e) {
            throw new IdentityBrokerException("Client secret is invalid.", e);
        }
    }

    private JsonWebToken generateClientToken(String teamId) {
        JsonWebToken jwt = new JsonWebToken();
        jwt.issuer(teamId);
        jwt.subject(getConfig().getClientId());
        jwt.audience(ISSUER);
        jwt.issuedNow();
        jwt.exp(jwt.getIat() + 30 * 60);
        return jwt;
    }
}
