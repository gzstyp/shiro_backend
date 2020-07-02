package com.fwtai.auth;

import com.fwtai.bean.LoginUser;
import com.fwtai.config.LocalPermission;
import com.fwtai.service.TokenService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * 为了能够被识别，选择继承AuthorizingRealm类
 * 处理角色和权限,接口请求时验证,是在登录之后执行的,即执行有需要验证角色或权限的地方才执行本方法?
 * 使用Shiro主要做3件事情，1）用户登录时做用户名密码校验；2）用户登录后收到请求时做JWT Token的校验；3）用户权限的校验
*/
public class JwtRealm extends AuthorizingRealm{

    @Resource
    private TokenService tokenService;

    /*必须重写,是个大坑,该方法是为了判断这个主体能否被本Realm处理，判断的方法是查看token是否为同一个类型*/
    @Override
    public boolean supports(final AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    //认证登录，在需要验证身份进行登录时，会通过这个接口，调用本方法进行审核，将身份信息返回，有误则抛出异常，在外层拦截
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(final AuthenticationToken auth) throws AuthenticationException{
        System.out.println("开始使用 token 认证身份信息……");
        final String access_token = (String) auth.getCredentials();
        // 解密获得token
        return new SimpleAuthenticationInfo(access_token,access_token,"jwtRealm");
    }

    /**
     * 只有当需要检测用户权限的时候才会调用此方法，例如checkRole,checkPermission之类的
    */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(final PrincipalCollection principals){
        System.out.println("需要检测用户权限的时候才会调用此方法");
        final LoginUser exist = LocalPermission.get();
        if(exist == null){
            tokenService.getLoginUser(getRequest());
        }
        final LoginUser loginUser = LocalPermission.get();
        final SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        // 添加角色
        if(loginUser.getRoleSet() != null){
            authorizationInfo.addRoles(loginUser.getRoleSet());
        }
        // 添加权限
        if(loginUser.getPermissionsSet() != null){
            authorizationInfo.addStringPermissions(loginUser.getPermissionsSet());
        }
        return authorizationInfo;
    }

    private final HttpServletRequest getRequest(){
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
    }
}