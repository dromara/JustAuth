package org.dromara.anduin.request;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.security.AbstractJwk;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.dromara.anduin.cache.AuthStateCache;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.config.AuthDefaultSource;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.scope.AuthAppleScope;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.AuthScopeUtils;
import org.dromara.anduin.utils.JsonUtils;
import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class AuthAppleRequest extends AuthDefaultRequest {

    private static final String AUD = "https://appleid.apple.com";

    private volatile PrivateKey privateKey;

    public AuthAppleRequest(AuthConfig config) {
        super(config, AuthDefaultSource.APPLE);
    }

    public AuthAppleRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.APPLE, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam("response_mode", "form_post")
                .queryParam(Keys.OAUTH2.SCOPE, this.getScopes(" ", false, AuthScopeUtils.getDefaultScopes(AuthAppleScope.values())))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        if (!StringUtils.isEmpty(authCallback.getError())) {
            throw new AuthException(authCallback.getError());
        }
        this.config.setClientSecret(this.getToken());
        // if failed will throw AuthException
        String response = doPostAuthorizationCode(authCallback.getCode());
        JsonNode accessTokenObject = toNode(response);
        // https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse
        AuthToken.AuthTokenBuilder builder = AuthToken.builder()
                .accessToken(getStringValue(accessTokenObject, Keys.OAUTH2.ACCESS_TOKEN))
                .expireIn(getIntValue(accessTokenObject, Keys.OAUTH2.EXPIRES_IN))
                .refreshToken(getStringValue(accessTokenObject, Keys.OAUTH2.REFRESH_TOKEN))
                .idToken(getStringValue(accessTokenObject, Keys.OIDC.ID_TOKEN))
                .tokenType(getStringValue(accessTokenObject, Keys.OAUTH2.TOKEN_TYPE));

        if (!StringUtils.isEmpty(authCallback.getUser())) {
            try {
                AppleUserInfo userInfo = JsonUtils.toObject(authCallback.getUser(), AppleUserInfo.class);
                builder.username(userInfo.getName().getFirstName() + " " + userInfo.getName().getLastName());
            } catch (Exception ignored) {
            }
        }
        return builder.build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
        String[] idToken = authToken.getIdToken().split("\\.");
        String payload = new String(urlDecoder.decode(idToken[1]));

        JsonNode userInfoObject = toNode(payload);
        // https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple#3383773
        return AuthUser.builder()
                .rawUserInfo(userInfoObject)
                .uuid(getStringValue(userInfoObject, Keys.USERINFO.SUB))
                .email(getStringValue(userInfoObject, Keys.USERINFO.EMAIL))
                .username(authToken.getUsername())
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        if (StringUtils.isEmpty(config.getClientId())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_CLIENT_ID, source);
        }
        if (StringUtils.isEmpty(config.getClientSecret())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_CLIENT_SECRET, source);
        }
        if (StringUtils.isEmpty(config.getKid())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_KID, source);
        }
        if (StringUtils.isEmpty(config.getTeamId())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_TEAM_ID, source);
        }
    }

    /**
     * 获取token
     *
     * @return jwt token
     * @see <a href="https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret">creating-a-client-secret</a>
     */
    private String getToken() {
        return Jwts.builder().header().add(AbstractJwk.KID.getId(), this.config.getKid()).and()
                .issuer(this.config.getTeamId())
                .subject(this.config.getClientId())
                .audience().add(AUD).and()
                .expiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(3)))
                .issuedAt(new Date())
                .signWith(getPrivateKey())
                .compact();
    }

    private PrivateKey getPrivateKey() {
        if (this.privateKey == null) {
            synchronized (this) {
                if (this.privateKey == null) {
                    try (PEMParser pemParser = new PEMParser(new StringReader(this.config.getClientSecret()))) {
                        JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();
                        PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
                        this.privateKey = pemKeyConverter.getPrivateKey(keyInfo);
                    } catch (IOException e) {
                        throw new AuthException("Failed to get apple private key", e);
                    }
                }
            }
        }
        return this.privateKey;
    }

    @Data
    static class AppleUserInfo {
        private AppleUsername name;
        private String email;
    }

    @Data
    static class AppleUsername {
        private String firstName;
        private String lastName;
    }
}
