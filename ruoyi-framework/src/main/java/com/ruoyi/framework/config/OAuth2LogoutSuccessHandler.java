package com.ruoyi.framework.config;

import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.framework.web.service.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class OAuth2LogoutSuccessHandler implements LogoutSuccessHandler {

    // Keycloak 登出地址
    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}/protocol/openid-connect/logout")
    private String keycloakLogoutUrl;
    // Keycloak 客户端 ID
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;
    // 登出后跳转地址
    @Value("${ruoyi.oauth2.failure-redirect}")
    private String logoutRedirect;

    // 注入若依 Token 服务
    private final TokenService tokenService;
    public OAuth2LogoutSuccessHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        // 2. 清除若依本地 Token（如果 authentication 是 null，就从 Token 里取用户名）
        LoginUser loginUser = tokenService.getLoginUser(request);
//        if (loginUser != null) {
//            tokenService.delLoginUser(loginUser.getToken());
//        }

        // 3. 构造 Keycloak 登出 URL
        String redirectUri = URLEncoder.encode(logoutRedirect, StandardCharsets.UTF_8.name());
        StringBuilder logoutUrl = new StringBuilder(keycloakLogoutUrl)
                .append("?client_id=").append(clientId)
                .append("&post_logout_redirect_uri=").append(redirectUri);

        if (loginUser != null && loginUser.getUser().getIdToken() != null) {
            logoutUrl.append("&id_token_hint=").append(loginUser.getUser().getIdToken());
        }

        // 3. 核心：返回JSON格式的URL给前端
        // 设置响应格式为JSON，编码为UTF-8
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // 构造返回结果
        JSONObject result = new JSONObject();
        result.put("code", 200);
        result.put("msg", "登出成功，返回Keycloak登出地址");
        result.put("logoutUrl", logoutUrl.toString());

        // 写入响应体
        try (PrintWriter writer = response.getWriter()) {
            writer.write(result.toString());
            writer.flush();
        }
    }

}