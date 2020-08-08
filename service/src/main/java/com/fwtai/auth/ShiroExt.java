package com.fwtai.auth;

import com.fwtai.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;

/**
 * shiro常用方法
*/
public class ShiroExt {

    /**
     * 是否是游客访问(用户没有登录)
    */
    public boolean isGuest() {
        return getSubject() == null || getSubject().getPrincipal() == null;
    }

    /**
     * 是否已经认证(包含登录和记住密码)
     */
    public boolean isUser() {
        return getSubject() != null && getSubject().getPrincipal() != null;
    }

    /**
     * 是否是登录通过认证的
     */
    public boolean isAuthenticated() {
        return getSubject() != null && getSubject().isAuthenticated();
    }

    /**
     * 是否是没有进行登录通过认证(记住密码)
     */
    public boolean isNotAuthenticated() {
        return !isAuthenticated();
    }

    /**
     * 获取当前用户信息
     */
    public String principal() {
        return principal(null);
    }

    /**
     * 获取当前用户信息
     *
     * @param property 用户属性名
     */
    public String principal(final String property) {
        return principal(property, User.class.getName());
    }

    /**
     * 获取当前用户信息
     *
     * @param property  用户属性名
     * @param className 用户class名
     */
    public String principal(final String property,final String className) {
        String strValue = null;
        if (getSubject() != null) {
            Object principal;
            if (className == null) {
                principal = getSubject().getPrincipal();
            } else {
                principal = getPrincipalFromClassName(className);
            }
            if (principal != null) {
                if (property == null) {
                    strValue = principal.toString();
                } else {
                    strValue = getPrincipalProperty(principal, property);
                }
            }
        }
        return strValue;
    }

    /**
     * 是否具有某个角色
     *
     * @param role 角色标识
     */
    public boolean hasRole(final String role) {
        return getSubject() != null && getSubject().hasRole(role);
    }

    /**
     * 是否没有有某个角色
     *
     * @param role 角色标识
     */
    public boolean lacksRole(final String role) {
        return !hasRole(role);
    }

    /**
     * 是否具有任意一个角色
     *
     * @param roles 角色标识
     */
    public boolean hasAnyRole(final String roles) {
        boolean hasAnyRole = false;
        final Subject subject = getSubject();
        if (subject != null) {
            for (String role : roles.split(",")) {
                if (subject.hasRole(role.trim())) {
                    hasAnyRole = true;
                    break;
                }
            }
        }
        return hasAnyRole;
    }

    /**
     * 是否具有某个权限
     *
     * @param p 权限标识
     */
    public boolean hasPermission(final String p) {
        return getSubject() != null && getSubject().isPermitted(p);
    }

    /**
     * 是否没有某个权限
     *
     * @param p 权限标识
     */
    public boolean lacksPermission(final String p) {
        return !hasPermission(p);
    }

    /**
     * 根据class获取当前用户
     */
    private Object getPrincipalFromClassName(final String className) {
        Object principal = null;
        try {
            final Class<?> clazz = Class.forName(className);
            principal = getSubject().getPrincipals().oneByType(clazz);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return principal;
    }

    /**
     * 获取当前用户的某个属性
     */
    private String getPrincipalProperty(final Object principal,final String property) {
        String strValue = null;
        try {
            final BeanInfo bi = Introspector.getBeanInfo(principal.getClass());
            boolean foundProperty = false;
            for (PropertyDescriptor pd : bi.getPropertyDescriptors()) {
                if (pd.getName().equals(property)) {
                    Object value = pd.getReadMethod().invoke(principal, (Object[]) null);
                    if (value != null) strValue = value.toString();
                    foundProperty = true;
                    break;
                }
            }
            if (!foundProperty) {
                String message = "Property [" + property + "] not found in principal of type [" + principal.getClass().getName() + "]";
                throw new RuntimeException(message);
            }
        } catch (Exception e) {
            String message = "Error reading property [" + property + "] from principal of type [" + principal.getClass().getName() + "]";
            throw new RuntimeException(message, e);
        }
        return strValue;
    }

    /**
     * 获取当前登录的用户
     */
    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }
}