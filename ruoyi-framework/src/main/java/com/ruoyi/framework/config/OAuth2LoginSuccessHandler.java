package com.ruoyi.framework.config;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.utils.KeycloakJwtUtils;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysMenuService;
import com.ruoyi.system.service.ISysUserService;
import org.apache.xmlbeans.impl.inst2xsd.SalamiSliceStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    // 若依 Token 服务（注入若依原生的 TokenService）
    private final TokenService tokenService;
    @Autowired
    private ISysUserService sysUserService;
    @Autowired
    private ISysMenuService menuService;
    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;
    @Autowired
    private ISysUserService userService;
    // 登录成功后跳转的前端地址
    @Value("${ruoyi.oauth2.success-redirect}")
    private String successRedirect;

    public OAuth2LoginSuccessHandler(TokenService tokenService, ISysUserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        // 获取 OAuth2 认证信息（此时 authentication 就是 OAuth2AuthenticationToken）
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauth2User = oauth2Token.getPrincipal();

        // 提取 Keycloak 用户信息
        String username = oauth2User.getAttribute("preferred_username"); // 用户名
//        String email = oauth2User.getAttribute("email"); // 邮箱
//        String nickname = oauth2User.getAttribute("name"); // 昵称

        // 从 SecurityContext 中获取 OAuth2AuthorizedClient（核心！）
        OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient("keycloak", authentication, request);
        String accessToken = null;
        if (authorizedClient != null) {
            OAuth2AccessToken token = authorizedClient.getAccessToken();
            if (token != null) {
                accessToken = token.getTokenValue();
            }
        }

        // 3. 解析 access_token 中的角色（如果获取到了）
        if (accessToken != null) {
            KeycloakJwtUtils jwtUtils = new KeycloakJwtUtils();
            Map<String, List<String>> roles = jwtUtils.parseRolesWithoutVerify(accessToken);
            System.out.println("领域角色(realmRoles): " + roles.get("realmRoles"));//[测试角色, offline_access, default-roles-ruoyi, uma_authorization]
            System.out.println("客户端角色(clientRoles): " + roles.get("clientRoles"));
        }

        String idToken = null;
        if (oauth2Token.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
            OidcIdToken oidcIdToken = oidcUser.getIdToken();
            if (oidcIdToken != null) {
                idToken = oidcIdToken.getTokenValue(); // 这就是你要的 id_token
            }
        }
        String sub = null;
        if (oauth2Token.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
            OidcUserInfo oidcUserInfo = oidcUser.getUserInfo();
            if (oidcUserInfo != null && oidcUserInfo.getClaims() != null) {
                sub = oidcUserInfo.getClaims().get("sub").toString();
            }
        }
        // 2. 适配若依逻辑：查询/创建本地用户（调用若依的用户服务）
        SysUser user = sysUserService.selectUserByUserName(username);
        if (user == null) {
            // 若本地无该用户，自动创建（需根据若依用户表结构调整）
            user = new SysUser();
            user.setUserName(username);
            user.setNickName(username);
            user.setEmail("");
            user.setPassword(new BCryptPasswordEncoder().encode("Dtnsh@855000")); // 初始密码
            user.setStatus("0"); // 启用
            user.setIdToken(idToken);
            user.setKeycloakId(sub);
            user.setAccessToken(accessToken);
            sysUserService.insertUser(user);
        }else {
            SysUser updateUser = new SysUser();
            updateUser.setUserId(user.getUserId());
            updateUser.setIdToken(idToken);
            updateUser.setKeycloakId(sub);
            updateUser.setAccessToken(accessToken);
            sysUserService.updateUser(updateUser);
        }

        // 4. 生成若依的 Token（适配若依的权限体系）
        LoginUser loginUser = new LoginUser();
        loginUser.setUserId(user.getUserId());
        // 加载用户权限（复用若依原有逻辑）
        loginUser.setPermissions(menuService.selectMenuPermsByUserId(user.getUserId()));
        loginUser.setUser(user);

        // 4. 生成Token并返回（和若依原有登录接口返回格式一致）
        String token = tokenService.createToken(loginUser);

        String redirectUrl = "http://localhost:80/login?token=" + URLEncoder.encode(token, "UTF-8");
        response.sendRedirect(redirectUrl);
    }
}