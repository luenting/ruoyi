package com.ruoyi.common.utils;
import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.core.domain.AjaxResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Keycloak JWT Token解析工具类
 */
@Component
public class KeycloakJwtUtils {

    // Keycloak公钥（从Keycloak后台获取：Realms → ruoyi → Keys → 选择RS256 → Public Key）
    @Value("${keycloak.public-key}")
    private String publicKey;

    /**
     * 解析Keycloak的access_token，获取所有角色
     */
    public Map<String, List<String>> parseRolesFromToken(String accessToken) {
        try {
            // 1. 加载公钥（验证Token合法性，可选：若信任Keycloak可跳过验证）
            PublicKey pubKey = getPublicKey();
            // 2. 使用旧版 API 解析 Token
            Claims claims = Jwts.parser()
                    .setSigningKey(pubKey)
                    .parseClaimsJws(accessToken)
                    .getBody();

            // 3. 提取领域角色
            Map<String, List<String>> realmAccess = (Map<String, List<String>>) claims.get("realm_access");
            List<String> realmRoles = realmAccess != null ? realmAccess.get("roles") : null;

            // 4. 提取客户端角色（替换为你的clientId：ruoyi）
            Map<String, Map<String, List<String>>> resourceAccess = (Map<String, Map<String, List<String>>>) claims.get("resource_access");
            Map<String, List<String>> clientAccess = resourceAccess != null ? resourceAccess.get("ruoyi") : null;
            List<String> clientRoles = clientAccess != null ? clientAccess.get("roles") : null;

            // 5. 返回角色（领域角色+客户端角色）
            Map<String, List<String>> rolesMap = new HashMap<>();
            rolesMap.put("realmRoles", realmRoles);
            rolesMap.put("clientRoles", clientRoles);
            return rolesMap;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("解析Keycloak Token角色失败：" + e.getMessage());
        }
    }

    /**
     * 获取Keycloak公钥（用于验证Token）
     */
    private PublicKey getPublicKey() throws Exception {
        // 格式化公钥（补充PKCS#8格式头和尾）
        String publicKeyPEM = publicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        // 解码公钥
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 简化版：不验证Token签名，直接解析角色（测试用）
     */
    public Map<String, List<String>> parseRolesWithoutVerify(String accessToken) {
        try {
            // 1. 拆分 JWT：header.payload.signature
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format");
            }

            // 2. Base64 解码 Payload 部分
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            JSONObject claims = JSONObject.parseObject(payloadJson);

            // 3. 提取领域角色
            JSONObject realmAccess = claims.getJSONObject("realm_access");
            List<String> realmRoles = realmAccess != null ? realmAccess.getList("roles", String.class) : null;

            // 4. 提取客户端角色（替换为你的 clientId：ruoyi）
            JSONObject resourceAccess = claims.getJSONObject("resource_access");
            JSONObject clientAccess = resourceAccess != null ? resourceAccess.getJSONObject("ruoyi") : null;
            List<String> clientRoles = clientAccess != null ? clientAccess.getList("roles", String.class) : null;

            // 5. 兼容 Java 8，用 HashMap 返回
            Map<String, List<String>> rolesMap = new HashMap<>();
            rolesMap.put("realmRoles", realmRoles);
            rolesMap.put("clientRoles", clientRoles);
            return rolesMap;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("解析 Keycloak Token 角色失败：" + e.getMessage());
        }
    }
}