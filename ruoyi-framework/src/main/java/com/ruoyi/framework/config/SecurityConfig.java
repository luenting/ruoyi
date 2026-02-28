package com.ruoyi.framework.config;

import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;
import com.ruoyi.framework.config.properties.PermitAllUrlProperties;
import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;

/**
 * spring security配置
 * 
 * @author ruoyi
 */
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
public class SecurityConfig
{
    /**
     * 自定义用户认证逻辑
     */
    @Autowired
    private ISysUserService userService;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private OAuth2LogoutSuccessHandler oauth2LogoutSuccessHandler;

    
    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * token认证过滤器
     */
    @Autowired
    private JwtAuthenticationTokenFilter authenticationTokenFilter;
    
    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;

    /**
     * 允许匿名访问的地址
     */
    @Autowired
    private PermitAllUrlProperties permitAllUrl;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    // ========== 注入自定义的Keycloak登录成功处理器（需提前定义） ==========
    @Bean
    public OAuth2LoginSuccessHandler keycloakLoginSuccessHandler() {
        return new OAuth2LoginSuccessHandler(tokenService, userService); // 注入若依的TokenService和UserService
    }

    // ========== 注入自定义的Keycloak登出成功处理器（需提前定义） ==========
    @Bean
    public OAuth2LogoutSuccessHandler keycloakLogoutSuccessHandler() {
        return new OAuth2LogoutSuccessHandler(tokenService); // 注入若依的TokenService
    }

    // ========== 关键修改3：核心安全过滤链配置 ==========
    // 替换若依默认的表单登录为 OAuth2 登录
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // CSRF禁用（若依原生，保留）
                .csrf(csrf -> csrf.disable())
                // 禁用HTTP响应标头（若依原生，保留）
                .headers((headersCustomizer) -> {
                    headersCustomizer.cacheControl(cache -> cache.disable()).frameOptions(options -> options.sameOrigin());
                })
                // 认证失败处理类（若依原生，保留）
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                // 关键：若依无状态 + OAuth2 兼容（允许临时Session存储OAuth2授权码）
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 改为IF_REQUIRED，兼容OAuth2
                        .maximumSessions(1) // 限制单用户登录（可选）
                )
                // 注解标记允许匿名访问的url（若依原生，补充OAuth2放行）
                .authorizeHttpRequests((requests) -> {
                    permitAllUrl.getUrls().forEach(url -> requests.antMatchers(url).permitAll());
                    // 若依原生放行
                    requests.antMatchers("/login","/register", "/captchaImage").permitAll()
                            // 核心：放行OAuth2授权入口和回调地址
                            .antMatchers("/oauth2/authorization/keycloak", "/login/oauth2/code/**", "/system/keycloak/**").permitAll()
                            // 静态资源放行（若依原生）
                            .antMatchers(HttpMethod.GET, "/", "/*.html", "/**/*.html", "/**/*.css", "/**/*.js", "/profile/**").permitAll()
                            // 所有请求需认证（若依原生）
                            .anyRequest().authenticated();
                })
                // ========== OAuth2 Login 核心配置（适配若依） ==========
                .oauth2Login(oauth2 -> oauth2
                        // OAuth2登录入口（前端跳转这个地址触发Keycloak授权）
                        .loginPage("/oauth2/authorization/keycloak")
                        // 自定义登录成功处理器（生成若依JWT Token，核心）
                        .successHandler(keycloakLoginSuccessHandler())
                        // 登录失败处理器（返回JSON，适配若依前后端分离）
                        .failureHandler((request, response, exception) -> {
                            response.setContentType("application/json;charset=UTF-8");
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.getWriter().write("{\"code\":401,\"msg\":\"Keycloak登录失败：" + exception.getMessage() + "\"}");
                        })
                )
                // ========== 登出配置（集成Keycloak登出） ==========
                .logout(logout -> logout
                        .logoutUrl("/logout")
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // 强制支持 GET 请求
                        .logoutSuccessHandler(oauth2LogoutSuccessHandler)
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                )
                // ========== 过滤器顺序（关键：修复执行顺序） ==========
                // 若依JWT过滤器：放在OAuth2过滤器之后，避免拦截OAuth2回调
                .addFilterBefore(authenticationTokenFilter, OAuth2LoginAuthenticationFilter.class)
                // CORS过滤器（若依原生，保留顺序）
                .addFilterBefore(corsFilter, CsrfFilter.class)
                .addFilterBefore(corsFilter, LogoutFilter.class)
                .build();
    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
}
