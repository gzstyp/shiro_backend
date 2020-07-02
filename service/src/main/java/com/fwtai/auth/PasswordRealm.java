package com.fwtai.auth;

import com.fwtai.entity.User;
import com.fwtai.service.web.UserService;
import com.fwtai.tool.ToolSHA;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;
import java.util.HashMap;

/**
 * 使用密码登录Realm，为了能够被识别，选择继承AuthorizingRealm类
*/
public class PasswordRealm extends AuthorizingRealm{

    @Resource
    private UserService userService;

    /*必须重写,是个大坑,该方法是为了判断这个主体能否被本Realm处理，判断的方法是查看token是否为同一个类型*/
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof CustomizedToken;
    }

    /**
     * 获取授权信息，这个方法是用来添加身份信息的，本项目计划为管理员提供网站后台，所以这里不需要身份信息，返回一个简单的即可
     * @param principals principals
     * @return AuthorizationInfo
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    /**
     * 获取认证身份信息,返回安全数据的身份信息，在需要验证身份进行登录时，会通过这个接口，调用本方法进行审核，将身份信息返回，有误则抛出异常，在外层拦截
     * @param authenticationToken authenticationToken
     * @return AuthenticationInfo
     * @throws AuthenticationException AuthenticationException
    */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(final AuthenticationToken authenticationToken) throws AuthenticationException{
        final CustomizedToken token = (CustomizedToken) authenticationToken;
        final String username = token.getUsername();
        final String password = new String(token.getPassword());
        final HashMap<String,String> params = new HashMap<>(2);
        final String encoder = ToolSHA.encoder(password,username);
        params.put("username",username);
        params.put("password",encoder);
        final User user = userService.queryLogin(params);
        if(user == null){
            userService.updateErrors(username);
            final User inexistence = userService.queryUser(username);
            if(inexistence != null){
                if(inexistence.getError() < 0){
                    throw new ExcessiveAttemptsException("当前帐号或密码连续错误3次<br/>已被系统临时锁定<br/>请在"+inexistence.getErrorTime()+"后重新登录");
                }
                if (inexistence.getErrorCount() >= 3){
                    userService.updateLoginTime(username);/*当错误3次时更新错误的时刻就锁定*/
                    throw new ExcessiveAttemptsException("当前帐号或密码连续错误3次<br/>已被系统临时锁定,请30分钟后重试");
                }
            }
            throw new UnknownAccountException("帐号或密码错误");
        }
        if(user.getError() < 0){
            throw new ExcessiveAttemptsException("当前帐号或密码连续错误3次<br/>已被系统临时锁定<br/>请在"+user.getErrorTime()+"后重新登录");
        }
        if(user.getEnabled() == 1){
            throw new UnknownAccountException("账号已被禁用冻结");
        }
        final ByteSource credentialsSalt = ByteSource.Util.bytes(ToolSHA.encryptHash(username));
        //在这里将principal换为用户的user,即已认证的身份信息
        return new SimpleAuthenticationInfo(user,encoder,credentialsSalt,"passwordRealm");//如果报错 AuthenticationException 请注意 encoder 是否需要加密
    }
}