package com.ruoyi.web.controller.system;

import com.ruoyi.common.core.domain.AjaxResult;
import com.ruoyi.framework.web.service.TokenService;
import com.ruoyi.system.service.ISysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Keycloak单点登出(Backchannel Logout)回调控制器
 * 接收Keycloak的登出通知，清理若依本地会话/Token
 */
@RestController
@RequestMapping("/system/keycloak")
public class KeycloakController {

    /**
     * 注入若依Token服务（用于清理登录Token）(暂不实现)
     */
    @Autowired
    private TokenService tokenService;
    @Autowired
    private ISysUserService sysUserService;

    /**
     * Keycloak Backchannel Logout回调接口
     * 注意：
     * 1. 请求方式必须是POST
     * 2. Content-Type为application/json
     * 3. Keycloak会自动向此接口发送登出请求
     */
    @PostMapping("/logout/backchannel/callback")
    public AjaxResult backchannelLogout(
            @RequestBody Map<String, Object> logoutRequest,
            HttpServletRequest request) {
        try {
            // ========== 步骤1：解析Keycloak传递的登出参数 ==========
            // sub：用户在Keycloak中的唯一标识（必传）
            String keycloakUserId = (String) logoutRequest.get("sub");
            // sid：Keycloak会话ID（可选，可用于精准清理）
            String sessionId = (String) logoutRequest.get("sid");

            if (keycloakUserId == null || keycloakUserId.isEmpty()) {
                return AjaxResult.error("回调参数缺失：未获取到Keycloak用户标识(sub)");
            }
            System.out.println("接收到Keycloak单点登出回调：用户ID=" + keycloakUserId + "，会话ID=" + sessionId);

            // ========== 步骤2：清理若依本地关联资源 ==========
            // 2.1 方式1：根据Keycloak用户ID清理若依Token（核心！）
            // 注意：需要先将Keycloak的sub与若依用户ID关联（比如登录时存入数据库/Redis）
            // 这里假设你在登录时已将keycloakUserId映射为若依的userId
            String ruyiUserId = sysUserService.selectUserByKeycloakId(sessionId).getUserId().toString();;
            if (ruyiUserId != null) {
                // 清理该用户的所有登录Token（若依默认存在Redis）
                tokenService.delLoginUser(ruyiUserId);
                System.out.println("已清理若依用户[" + ruyiUserId + "]的所有登录Token");
            }

            // 2.2 方式2：清除当前请求的会话（可选）
            request.getSession().invalidate();

            // ========== 步骤3：返回成功响应给Keycloak ==========
            // Keycloak要求响应状态码为200，无需返回额外内容
            return AjaxResult.success("单点登出成功，已清理若依本地资源");

        } catch (Exception e) {
            e.printStackTrace();
            // 即使出错，也返回200（避免Keycloak重复回调）
            return AjaxResult.error("单点登出处理失败：" + e.getMessage());
        }
    }
}