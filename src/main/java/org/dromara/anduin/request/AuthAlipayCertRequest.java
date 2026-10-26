package org.dromara.anduin.request;


import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.AlipayConfig;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.request.AlipayUserInfoShareRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.alipay.api.response.AlipayUserInfoShareResponse;
import org.dromara.anduin.config.AuthConfig;
import org.dromara.anduin.constant.Keys;
import org.dromara.anduin.enums.AuthResponseStatus;
import org.dromara.anduin.enums.AuthUserGender;
import org.dromara.anduin.exception.AuthException;
import org.dromara.anduin.http.UrlBuilder;
import org.dromara.anduin.model.AuthCallback;
import org.dromara.anduin.model.AuthResponse;
import org.dromara.anduin.model.AuthToken;
import org.dromara.anduin.model.AuthUser;
import org.dromara.anduin.utils.JsonUtils;

import org.apache.commons.lang3.StringUtils;

import static org.dromara.anduin.config.AuthDefaultSource.ALIPAY;

/**
 * 支付宝证书模式登录
 *
 * @since 1.16.7
 */
public class AuthAlipayCertRequest extends AbstractAuthAlipayRequest {

    private final AlipayClient alipayClient;

    public AuthAlipayCertRequest(AuthConfig config, AlipayConfig alipayConfig) {
        super(config, ALIPAY);
        try {
            this.alipayClient = new DefaultAlipayClient(alipayConfig);
        } catch (AlipayApiException e) {
            throw new AuthException(e);
        }
    }

    @Override
    protected void checkCode(AuthCallback authCallback) {
        if (StringUtils.isEmpty(authCallback.getAuth_code())) {
            throw new AuthException(AuthResponseStatus.ILLEGAL_CODE, source);
        }
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        AlipaySystemOauthTokenRequest request = new AlipaySystemOauthTokenRequest();
        request.setGrantType(Keys.OAUTH2.GRANT_TYPES.AUTHORIZATION_CODE);
        request.setCode(authCallback.getAuth_code());
        AlipaySystemOauthTokenResponse accessTokenResponse;
        try {
            accessTokenResponse = this.alipayClient.certificateExecute(request);
        } catch (Exception e) {
            throw new AuthException(e);
        }
        if (!accessTokenResponse.isSuccess()) {
            throw new AuthException(accessTokenResponse.getSubMsg());
        }

        return getAccessToken(accessTokenResponse);
    }


    /**
     * 刷新access token （续期）
     *
     * @param authToken 登录成功后返回的Token信息
     * @return AuthResponse
     */
    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        AlipaySystemOauthTokenRequest request = new AlipaySystemOauthTokenRequest();
        request.setGrantType(Keys.OAUTH2.REFRESH_TOKEN);
        request.setRefreshToken(authToken.getRefreshToken());
        AlipaySystemOauthTokenResponse response = null;
        try {
            response = this.alipayClient.certificateExecute(request);
        } catch (Exception e) {
            throw new AuthException(e);
        }
        if (!response.isSuccess()) {
            throw new AuthException(response.getSubMsg());
        }

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getAccessToken(response))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        AlipayUserInfoShareRequest request = new AlipayUserInfoShareRequest();
        AlipayUserInfoShareResponse response = null;
        try {
            response = this.alipayClient.certificateExecute(request, accessToken);
        } catch (AlipayApiException e) {
            throw new AuthException(e.getErrMsg(), e);
        }
        if (!response.isSuccess()) {
            throw new AuthException(response.getSubMsg());
        }

        String province = response.getProvince(), city = response.getCity();
        String location = String.format("%s %s", StringUtils.isEmpty(province) ? "" : province, StringUtils.isEmpty(city) ? "" : city);

        return AuthUser.builder()
                .rawUserInfo(toNode(JsonUtils.toJson(response)))
                .uuid(response.getOpenId())
                .username(StringUtils.isEmpty(response.getUserName()) ? response.getNickName() : response.getUserName())
                .nickname(response.getNickName())
                .avatar(response.getAvatar())
                .location(location)
                .gender(AuthUserGender.getRealGender(response.getGender()))
                .token(authToken)
                .source(source.toString())
                .build();
    }


    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2.APP_ID, config.getClientId())
                .queryParam(Keys.OAUTH2.SCOPE, "auth_user")
                .queryParam(Keys.OAUTH2.REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2.STATE, getRealState(state))
                .build();
    }
}
