package com.fwtai.auth;

import com.fwtai.tool.ToolSHA;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 加入进来扫描所有的接口并放行，达到识别token并标记登录的需求。
 * 主要是初始化Realm，注册Filter，定义filterChain;使用Shiro主要做3件事情，1）用户登录时做用户名密码校验；2）用户登录后收到请求时做JWT Token的校验；3）用户权限的校验
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020/4/18 9:23
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
@Configuration
public class ShiroConfiguration{

    /**
     * 开启shiro权限注解,这个不要开启,否则切换数据源出问题
     * @return DefaultAdvisorAutoProxyCreator
    */
    /*@Bean
    public static DefaultAdvisorAutoProxyCreator creator(){
        final DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }*/

    /**
     * 开启shiro aop注解支持.
     * 使用代理方式;所以需要开启代码支持;
     * @param securityManager 安全管理器
     * @return AuthorizationAttributeSourceAdvisor
    */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(final SecurityManager securityManager) {
        final AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(securityManager);
        return advisor;
    }

    /**
     * 密码登录或验证码登录时使用该匹配器进行匹配
     * @return HashedCredentialsMatcher
    */
    @Bean("hashedCredentialsMatcher")
    public HashedCredentialsMatcher hashedCredentialsMatcher(){
        final HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        // 设置哈希算法名称
        matcher.setHashAlgorithmName(ToolSHA.ALGORITHMNAME);
        // 设置哈希迭代次数
        matcher.setHashIterations(ToolSHA.HASHITERATIONS);
        // 设置存储凭证十六进制编码
        matcher.setStoredCredentialsHexEncoded(true);
        return matcher;
    }

    /**
     * 使用密码登录Realm
     * @param matcher 密码匹配器
     * @return PasswordRealm
    */
    @Bean
    public PasswordRealm passwordRealm(@Qualifier("hashedCredentialsMatcher") HashedCredentialsMatcher matcher){
        final PasswordRealm userRealm = new PasswordRealm();
        userRealm.setCredentialsMatcher(matcher);
        return userRealm;
    }

    /**
     * 使用验证码登录Realm
     * @param matcher 密码匹配器
     * @return CodeRealm
    */
    @Bean
    public CodeRealm codeRealm(@Qualifier("hashedCredentialsMatcher") HashedCredentialsMatcher matcher){
        final CodeRealm codeRealm = new CodeRealm();
        codeRealm.setCredentialsMatcher(matcher);
        return codeRealm;
    }

    @Bean
    public JwtRealm jwtRealm(){
        return new JwtRealm();
    }

    /**
     * Shiro内置过滤器，可以实现拦截器相关的拦截器
     *    常用的过滤器：
     *      anon：无需认证（登录）可以访问
     *      authc：必须认证才可以访问
     *      user：如果使用rememberMe的功能可以直接访问
     *      perms：该资源必须得到资源权限才可以访问
     *      role：该资源必须得到角色权限才可以访问
    */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(@Qualifier("securityManager") SecurityManager securityManager){
        final ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        // 设置 SecurityManager
        bean.setSecurityManager(securityManager);
        final Map<String, String> filterMap = new LinkedHashMap<>();
        //以下是访问是不通过我们的Filter
        filterMap.put("/static/**","anon");
        filterMap.put("/user/login","anon");
        filterMap.put("/user/logout","logout");
        filterMap.put("/user/renewalToken","anon");//更新令牌
        filterMap.put("/*.js","anon");
        filterMap.put("/*.css","anon");
        //从这里开始，是我为解决问题增加的，为swagger页面放行
        filterMap.put("/swagger-ui.html", "anon");
        filterMap.put("/swagger-resources/**","anon");
        filterMap.put("/v2/**", "anon");
        filterMap.put("/webjars/**", "anon");
        filterMap.put("/images/**", "anon");

        final Map<String, Filter> filter = new HashMap<>(1);
        filter.put("jwt", new JwtFilter());
        bean.setFilters(filter);
        filterMap.put("/**", "jwt");
        bean.setFilterChainDefinitionMap(filterMap);
        return bean;
    }

    @Bean
    public ShiroRealmAuthenticator shiroRealmAuthenticator(){
        //自己重写的ModularRealmAuthenticator
        final ShiroRealmAuthenticator modularRealmAuthenticator = new ShiroRealmAuthenticator();
        modularRealmAuthenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        return modularRealmAuthenticator;
    }

    //SecurityManager 是 Shiro 架构的核心，通过它来链接Realm和用户(文档中称之为Subject)
    @Bean
    public SecurityManager securityManager(@Qualifier("passwordRealm") PasswordRealm passwordRealm,
                                           @Qualifier("codeRealm") CodeRealm codeRealm,
                                           @Qualifier("jwtRealm") JwtRealm jwtRealm,
                                           @Qualifier("shiroRealmAuthenticator") ShiroRealmAuthenticator shiroRealmAuthenticator) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 设置realm
        securityManager.setAuthenticator(shiroRealmAuthenticator);
        final List<Realm> realms = new ArrayList<>();
        // 添加多个realm
        realms.add(passwordRealm);
        realms.add(codeRealm);
        realms.add(jwtRealm);
        securityManager.setRealms(realms);
        //关闭shiro自带的session，详情见文档
        final DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        securityManager.setSubjectDAO(subjectDAO);
        return securityManager;
    }
}