package com.fwtai.auth;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 一个用于Shiro使用的Authentication，因为使用JWT需要有自己的身份信息，所以使用针对Token定制的信息
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020/4/19 10:03
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
 */
public class JwtToken implements AuthenticationToken {

    //封装，防止误操作
    private String token;

    /**
     * token作为两者进行提交，使用构造方法进行初始化
     * @param token 用户登录提交的用户名和密码的login()方法生成的token
     */
    public JwtToken(final String token) {
        this.token = token;
    }

    //在UserNamePasswordToken中，使用的是账号和密码来作为主体和签证,这里我们使用Token登录,两者的get都是获取token
    @Override
    public Object getPrincipal(){
        return token;
    }

    //在UserNamePasswordToken中，使用的是账号和密码来作为主体和签证,这里我们使用Token登录,两者的get都是获取token
    @Override
    public Object getCredentials() {
        return token;
    }
}