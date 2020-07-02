package com.fwtai.service;

import com.fwtai.bean.LoginUser;
import com.fwtai.config.ConfigFile;
import com.fwtai.config.LocalPermission;
import com.fwtai.config.LocalUserId;
import com.fwtai.service.web.UserService;
import com.fwtai.tool.ToolJWT;
import io.jsonwebtoken.Claims;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Service
public class TokenService{

    @Resource
    private UserService userService;

    /**
     * 获取当前登录的User对象及角色权限
     * @return LoginUser
    */
    public LoginUser getLoginUser(final HttpServletRequest request){
        final String access = request.getHeader(ConfigFile.ACCESS_TOKEN);
        final String parameter = request.getParameter(ConfigFile.ACCESS_TOKEN);
        final String token = access == null ? parameter : access;
        final Claims claims = ToolJWT.parser(token);
        final String userId = claims.getId();
        LocalUserId.set(userId);//存入 ThreadLocal,方便后续获取用户信息
        final List<String> roles = claims.get(userId,List.class);
        final LoginUser loginUser = new LoginUser();
        loginUser.setUserId(userId);
        loginUser.setRoleSet(roles);
        loginUser.setPermissionsSet(userService.getPermissions(userId));
        LocalPermission.set(loginUser);//存入 ThreadLocal,方便后续获取用户信息
        return loginUser;
    }
}