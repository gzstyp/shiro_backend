package com.fwtai.auth;

import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * 一个用于Shiro使用的Authentication，因为使用JWT需要有自己的身份信息，所以使用针对Token定制的信息
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020/4/19 18:25
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
public class CustomizedToken extends UsernamePasswordToken{

    /**
     * 登录类型,包含验证码及密码登录类型
    */
    private String loginType;

    //自定义登录token方法,username账号和password密码及登录方式,可选值:CodeRealm | PasswordRealm ,然后在类ShiroRealmAuthenticator的方法doAuthenticate()上使用
    public CustomizedToken(final String username,final String password,String loginType){
        super(username, password);
        this.loginType = loginType;
    }

    public String getLoginType() {
        return loginType;
    }

    public void setLoginType(String loginType) {
        this.loginType = loginType;
    }

    @Override
    public String toString(){
        return "loginType="+ loginType +",username=" + super.getUsername()+",password="+ String.valueOf(super.getPassword());
    }
}