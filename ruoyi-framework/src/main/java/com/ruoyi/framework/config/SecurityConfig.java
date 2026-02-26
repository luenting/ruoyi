package com.ruoyi.framework.config;

import com.alibaba.fastjson2.JSON;
import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysMenuService;
import com.ruoyi.system.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.filter.CorsFilter;
import com.ruoyi.framework.config.properties.PermitAllUrlProperties;
import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;
import com.ruoyi.framework.security.handle.LogoutSuccessHandlerImpl;

import java.net.URLEncoder;

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
    private UserDetailsService userDetailsService;
    @Autowired
    private ISysUserService sysUserService;
    @Autowired
    private ISysMenuService menuService;
    @Autowired
    private TokenService tokenService;

    
    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * 退出处理类
     */
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;

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

    /**
     * 身份验证实现
     */
    @Bean
    public AuthenticationManager authenticationManager()
    {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());
        return new ProviderManager(daoAuthenticationProvider);
    }
    // ========== 关键修改1：自定义 OAuth2 登录成功处理器 ==========
    // Keycloak 登录成功后，适配若依的用户会话、权限逻辑
    @Bean
    public AuthenticationSuccessHandler keycloakLoginSuccessHandler() {
        return (request, response, authentication) -> {
            // 1. 解析Keycloak返回的用户信息
            OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
            String username = oauth2Token.getPrincipal().getAttribute("preferred_username"); // Keycloak用户名

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
                sysUserService.insertUser(user);
            }

            // 3. 生成若依的JWT Token（复用若依原有工具类）
            LoginUser loginUser = new LoginUser();
            loginUser.setUserId(user.getUserId());
            // 加载用户权限（复用若依原有逻辑）
            loginUser.setPermissions(menuService.selectMenuPermsByUserId(user.getUserId()));
            loginUser.setUser(user);

            // 4. 生成Token并返回（和若依原有登录接口返回格式一致）
            String token = tokenService.createToken(loginUser);

            String redirectUrl = "http://localhost:80/login?token=" + URLEncoder.encode(token, "UTF-8");
            response.sendRedirect(redirectUrl);
        };
    }

    // ========== 关键修改2：自定义登出成功处理器（可选） ==========
    // 登出时同步退出 Keycloak
    @Bean
    public LogoutSuccessHandler keycloakLogoutSuccessHandler() {
        return (request, response, authentication) -> {
            // 1. 重定向到 Keycloak 登出地址（替换为你的 Keycloak 地址）
            String keycloakLogoutUrl = "http://localhost:8080/realms/master/protocol/openid-connect/logout?redirect_uri=" +
                    java.net.URLEncoder.encode("http://localhost:8081/login", "UTF-8");
            response.sendRedirect(keycloakLogoutUrl);
        };
    }

    // ========== 关键修改3：核心安全过滤链配置 ==========
    // 替换若依默认的表单登录为 OAuth2 登录
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // CSRF禁用，因为不使用session
                .csrf(csrf -> csrf.disable())
                // 禁用HTTP响应标头
                .headers((headersCustomizer) -> {
                    headersCustomizer.cacheControl(cache -> cache.disable()).frameOptions(options -> options.sameOrigin());
                })
                // 认证失败处理类
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                // 基于token，所以不需要session（保留原有逻辑）
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 注解标记允许匿名访问的url
                .authorizeHttpRequests((requests) -> {
                    permitAllUrl.getUrls().forEach(url -> requests.antMatchers(url).permitAll());
                    // 对于登录login 注册register 验证码captchaImage 允许匿名访问
                    requests.antMatchers("/login", "/register", "/captchaImage").permitAll()
                            // ========== 新增：放行Keycloak OAuth2回调地址 ==========
                            .antMatchers("/login/oauth2/code/**").permitAll()
                            // 静态资源，可匿名访问
                            .antMatchers(HttpMethod.GET, "/", "/*.html", "/**/*.html", "/**/*.css", "/**/*.js", "/profile/**").permitAll()
                            .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/*/api-docs", "/druid/**").permitAll()
                            // 除上面外的所有请求全部需要鉴权认证
                            .anyRequest().authenticated();
                })
                // ========== 新增：配置OAuth2登录（对接Keycloak） ==========
                .oauth2Login(oauth2 -> oauth2
                        // 自定义OAuth2登录成功处理器（生成若依JWT Token）
                        .successHandler(keycloakLoginSuccessHandler())
                        // 自定义认证失败处理器（可选）
                        .failureHandler((request, response, exception) -> {
                            response.setContentType("application/json;charset=UTF-8");
                            response.getWriter().write("{\"code\":401,\"msg\":\"Keycloak登录失败：" + exception.getMessage() + "\"}");
                        })
                )
                // 添加Logout filter（保留原有逻辑）
                .logout(logout -> logout.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler))
                // 添加JWT filter（保留原有逻辑）
                .addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                // 添加CORS filter（保留原有逻辑）
                .addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class)
                .addFilterBefore(corsFilter, LogoutFilter.class)
                .build();
    }


    /**
     * anyRequest          |   匹配所有请求路径
     * access              |   SpringEl表达式结果为true时可以访问
     * anonymous           |   匿名可以访问
     * denyAll             |   用户不能访问
     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
     * permitAll           |   用户可以任意访问
     * rememberMe          |   允许通过remember-me登录的用户访问
     * authenticated       |   用户登录后可访问
     */
//    @Bean
//    protected SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception
//    {
//        return httpSecurity
//            // CSRF禁用，因为不使用session
//            .csrf(csrf -> csrf.disable())
//            // 禁用HTTP响应标头
//            .headers((headersCustomizer) -> {
//                headersCustomizer.cacheControl(cache -> cache.disable()).frameOptions(options -> options.sameOrigin());
//            })
//            // 认证失败处理类
//            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
//            // 基于token，所以不需要session
//            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//            // 注解标记允许匿名访问的url
//            .authorizeHttpRequests((requests) -> {
//                permitAllUrl.getUrls().forEach(url -> requests.antMatchers(url).permitAll());
//                // 对于登录login 注册register 验证码captchaImage 允许匿名访问
//                requests.antMatchers("/login", "/register", "/captchaImage").permitAll()
//                    // 静态资源，可匿名访问
//                    .antMatchers(HttpMethod.GET, "/", "/*.html", "/**/*.html", "/**/*.css", "/**/*.js", "/profile/**").permitAll()
//                    .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/*/api-docs", "/druid/**").permitAll()
//                    // 除上面外的所有请求全部需要鉴权认证
//                    .anyRequest().authenticated();
//            })
//            // 添加Logout filter
//            .logout(logout -> logout.logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler))
//            // 添加JWT filter
//            .addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
//            // 添加CORS filter
//            .addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class)
//            .addFilterBefore(corsFilter, LogoutFilter.class)
//            .build();
//    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
}
