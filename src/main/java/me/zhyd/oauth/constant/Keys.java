package me.zhyd.oauth.constant;

/**
 * <p>Description: 字符串常量 </p>
 *
 * @author : gengwei.zheng
 * @date : 2025/9/11 11:22
 */
public interface Keys {

    public interface OAUTH2 {
        String APPID            = "appid";
        String APP_ID           = "app_id";
        String APP_KEY          = "app_key";
        String SECRET           = "secret";
        
        String CLIENT_ID        = "client_id";
        String CLIENT_SECRET    = "client_secret";
        
        String ACCESS_TOKEN     = "access_token";
        String CODE             = "code";
        String EXPIRES_IN       = "expires_in";
        String GRANT_TYPE       = "grant_type";
        String REDIRECT_URI     = "redirect_uri";
        String REFRESH_TOKEN    = "refresh_token";
        String RESPONSE_TYPE    = "response_type";
        String SCOPE            = "scope";
        String STATE            = "state";
        String TOKEN_TYPE       = "token_type";
        String OPEN_ID          = "open_id";
    
        public interface GRANT_TYPES {
            String AUTHORIZATION_CODE   = "authorization_code";
        }
    
        public interface SCOPES {
            String ADDRESS          = "address";
            String EMAIL            = "email";
            String OPENID           = "openid";
            String PHONE            = "phone";
            String PROFILE          = "profile";
            String NAME             = "name";
            String USER             = "user";
        }
    }
    
    public interface OIDC {
        String ID_TOKEN             = "id_token";
    }

    public interface USERINFO {
        String UNIONID              = "unionid";
        String UNION_ID             = "union_id";
        
        String ID                   = "id";
        String UID                  = "uid";
        String USERID               = "userid";
        String USER_ID              = "user_id";
        
        String SUB				  	= "sub";
        String USER                 = "user";
        String USERNAME             = "username";
        String NAME                 = "name";
        
        String NICKNAME             = "nickname";
        String DISPLAY_NAME         = "displayName";
        String SCREENNAME           = "screen_name";
        
        String GENDER               = "gender";
        String SEX                  = "sex";
        String PICTURE              = "picture";
        
        String EMAIL                = "email";
        String ADDRESS              = "address";
        
        String COMPANY              = "company";
        
        String COUNTRY              = "country";
        String CITY                 = "city";
        String PROVINCE             = "province";
        String LOCATION             = "location";
        
        String URL                  = "url";
        String AVATAR               = "avatar";
        String AVATAR_URL           = "avatar_url";
        
        String LANG                 = "lang";
        String MESSAGE              = "message";
        
        String DESCRIPTION          = "description";
        
    }
    
    public interface  PARAM {
        String CLIENT_ID            = "clientId";
        String CLIENT_SECRET        = "clientSecret";
        
    }
    
    public interface RESPONSE_FIELDS {
        String DATA                 = "data";
        String RESULT               = "result";
        String DESCRIPTION          = "description";
        String ERROR                = "error";
        String ERROR_CODE           = "error_code";
        String ERROR_DESCRIPTION    = "error_description";
        String ERRCODE              = "errcode";
        String ERRMSG               = "errmsg";
        String ERR_NO               = "error_no";
        String ERR_DESC             = "error_desc";
    }
    
    
}
