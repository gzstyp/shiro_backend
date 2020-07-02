package com.fwtai.auth;

import com.fwtai.config.ConfigFile;
import com.fwtai.config.LocalPermission;
import com.fwtai.config.LocalUserId;
import com.fwtai.config.RenewalToken;
import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJWT;
import com.fwtai.tool.ToolString;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 不要动它!!!
 *
 * 所有的请求都会先经过Filter，所以我们继承官方的BasicHttpAuthenticationFilter，并且重写鉴权的方法。
 *
 * @执行流程 代码的执行流程preHandle->isAccessAllowed->isLoginAttempt->executeLogin
 *
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020/4/18 8:39
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
public class JwtFilter extends BasicHttpAuthenticationFilter{

    /**
     * 1.对跨域提供支持
    */
    @Override
    protected boolean preHandle(final ServletRequest req,final ServletResponse res) throws Exception {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;
        req.setCharacterEncoding("UTF-8");
        response.setHeader("Access-control-Allow-Origin","*");
        response.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS,PUT,DELETE");
        response.setHeader("Access-Control-Allow-Headers",request.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (request.getMethod().equals(RequestMethod.OPTIONS.name())){
            response.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(req,res);
    }

    /**
     * 2.执行带token认证有效,在此处理token是否需要更换!!!
     * @param request ServletRequest
     * @param response ServletResponse
     * @param mappedValue mappedValue
     * @return 是否成功
    */
    @Override
    protected boolean isAccessAllowed(final ServletRequest request,final ServletResponse response,final Object mappedValue) {
        final HttpServletRequest req = (HttpServletRequest) request;
        final String refresh_token = ToolString.wipeString(req.getHeader(ConfigFile.REFRESH_TOKEN));
        final String access_token = ToolString.wipeString(req.getHeader(ConfigFile.ACCESS_TOKEN));
        final String url_refresh_token = ToolString.wipeString(req.getParameter(ConfigFile.REFRESH_TOKEN));
        final String url_access_token = ToolString.wipeString(req.getParameter(ConfigFile.ACCESS_TOKEN));
        final String refresh = refresh_token == null ? url_refresh_token : refresh_token;
        final String access = access_token == null ? url_access_token : access_token;
        if(refresh != null && access != null){
            return executeLogin(request,response);
        }
        // 如果请求头不存在 Token，则可能是执行登陆操作或者是游客状态访问，无需检查 token，直接返回 true
        return true;
    }
 
    /**
     * ３.执行登录,在此处理token是否需要更换
    */
    @Override
    protected boolean executeLogin(final ServletRequest request,final ServletResponse response){
        final HttpServletRequest req = (HttpServletRequest) request;
        final String refresh_token = ToolString.wipeString(req.getHeader(ConfigFile.REFRESH_TOKEN));
        final String access_token = ToolString.wipeString(req.getHeader(ConfigFile.ACCESS_TOKEN));
        final String url_refresh_token = ToolString.wipeString(req.getParameter(ConfigFile.REFRESH_TOKEN));
        final String url_access_token = ToolString.wipeString(req.getParameter(ConfigFile.ACCESS_TOKEN));
        final String refresh = refresh_token == null ? url_refresh_token : refresh_token;
        final String access = access_token == null ? url_access_token : access_token;
        if(refresh == null || access == null){
            ToolClient.responseJson(ToolClient.tokenInvalid(),(HttpServletResponse)response);
            return false;
        }
        try {
            ToolJWT.parser(refresh);
        } catch (final Exception e){
            if(e instanceof ExpiredJwtException){
                try {
                    ToolJWT.parser(access);
                } catch (final Exception exception){
                    System.out.println("你真的需要重新登录1");
                    ToolClient.responseJson(ToolClient.tokenInvalid(),(HttpServletResponse)response);
                    return false;
                }
                RenewalToken.set(access);//存入 ThreadLocal,说明需要更新令牌标识,方便后续获取在ToolClient.responseJson()返回时添加标识,可以使redis来防止重复更新令牌,可以设置和前端一样在2分钟之内不可以重复更换令牌
            }else if(e instanceof JwtException){
                ToolClient.responseJson(ToolClient.tokenInvalid(),(HttpServletResponse)response);
                return false;
            }
        }
        try {
            ToolJWT.parser(access);
        } catch (final Exception exception){
            System.out.println("你真的需要重新登录2");
            if(exception instanceof JwtException){
                ToolClient.responseJson(ToolClient.tokenInvalid(),(HttpServletResponse)response);
                return false;
            }
        }
        final JwtToken jwtToken = new JwtToken(access);
        try {
            // 提交给realm进行登入，如果错误他会抛出异常并被捕获
            getSubject(request, response).login(jwtToken);//getSubject(request, response).login(token);这一步就是提交给了realm进行处理
            // 如果没有抛出异常则代表登入成功，返回true
        } catch (final IncorrectCredentialsException e){
            ToolClient.responseJson(ToolClient.tokenInvalid(),(HttpServletResponse)response);
            return false;
        }
        // 如果没有抛出异常则代表登入成功，返回true
        return true;
    }

    @Override
    public void afterCompletion(final ServletRequest request,final ServletResponse response,final Exception exception) throws Exception{
        RenewalToken.remove();
        LocalPermission.remove();
        LocalUserId.remove();
        super.afterCompletion(request,response,exception);
    }
}