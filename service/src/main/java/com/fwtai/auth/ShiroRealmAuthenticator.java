package com.fwtai.auth;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;

import java.util.ArrayList;
import java.util.Collection;

/**
 *  拦截Realm认证器,拦截到类名称XxxRealm后再调用执行对应的认证器,本项目共有3个[PasswordRealm;CodeRealm;JwtRealm],比如是PasswordRealm那就走com.fwtai.auth.PasswordRealm的方法doGetAuthenticationInfo,拦截肯定是优先于 PasswordRealm|CodeRealm|JwtRealm,然后再从这3个中选择指定是认证类进行认证
 * @author lixiao
 * @date 2019/7/31 20:48
 *  当配置了多个Realm时，我们通常使用的认证器是shiro自带的
 *  org.apache.shiro.authc.pam.ModularRealmAuthenticator，
 *  其中决定使用的Realm的是doAuthenticate()方法
*/
public class ShiroRealmAuthenticator extends ModularRealmAuthenticator{

    @Override
    protected AuthenticationInfo doAuthenticate(final AuthenticationToken authenticationToken) throws AuthenticationException{
        System.err.println("执行顺序2-需要验证身份上才调用本方法,含登录,否则直走顺序1和顺序3");
        // 判断getRealms()是否返回为空
        assertRealmsConfigured();
        // 所有Realm
        final Collection<Realm> realms = getRealms();//此处是Realms的集合是在类com.fwtai.auth.ShiroConfiguration注入添加的类名称
        // 登录类型对应的所有Realm
        final Collection<Realm> typeRealms = new ArrayList<>(1);
        if(authenticationToken instanceof JwtToken){
            final JwtToken jwtToken = (JwtToken) authenticationToken;//带token时才走这个方法
            for(final Realm realm : realms){// PasswordRealm;CodeRealm;JwtRealm;
                if (realm.getName().contains("JwtRealm")){//这个值类的名称,它是在类com.fwtai.auth.ShiroConfig里添加注入的
                    typeRealms.add(realm);
                }
            }
            return doSingleRealmAuthentication(typeRealms.iterator().next(),jwtToken);
        }else{
            final CustomizedToken customizedToken = (CustomizedToken) authenticationToken;
            // 登录类型,包含验证码及密码登录类型
            final String loginType = customizedToken.getLoginType();
            for (final Realm realm : realms) {
                if (realm.getName().contains(loginType)){
                    typeRealms.add(realm);
                }
            }
            // 判断是单Realm还是多Realm
            return typeRealms.size() == 1 ? doSingleRealmAuthentication(typeRealms.iterator().next(),customizedToken) : doMultiRealmAuthentication(typeRealms,customizedToken);
        }
    }
}