package com.fwtai.web.controller;

import com.fwtai.bean.PageFormData;
import com.fwtai.service.web.UserService;
import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.List;

/**
 * 用户管理接口入口
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-03-13 17:14
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
@RestController
@RequestMapping("/user")
public class UserController{

    @Resource
    private UserService userService;

    @PostMapping(value = "/login")
    public void login(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.login(request),response);
    }

    @GetMapping(value = "/logout")
    public void logout(final HttpServletResponse response){
        ToolClient.responseJson(userService.logout(),response);
    }

    @PostMapping(value = "/renewalToken")
    public void renewalToken(final HttpServletRequest request,final HttpServletResponse response){
        final PageFormData formData = ToolClient.getFormData(request);
        final String access_token = formData.getString("accessToken");
        try {
            final Claims claims = ToolJWT.parser(access_token);
            final String userId = claims.getId();
            final List<String> permissionRole = claims.get(userId,List.class);
            final HashMap<String,String> result = userService.buildToken(userId,permissionRole);
            System.err.println("-----------已成功更新令牌并返回-----------");
            ToolClient.responseJson(ToolClient.queryJson(result),response);
        } catch (final JwtException exception){
            System.out.println("你真的需要重新登录");
            ToolClient.responseJson(ToolClient.tokenInvalid(),response);
        }
    }

    /**添加*/
    @RequiresPermissions("user_btn_add")
    @PostMapping(value = "/add",name = "user_btn_add")
    public void add(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.add(ToolClient.getFormData(request)),response);
    }

    /**编辑*/
    @RequiresPermissions("user_row_edit")
    @PostMapping(value = "/edit",name = "user_row_edit")
    public void edit(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.edit(ToolClient.getFormData(request)),response);
    }

    /**删除-单行*/
    @RequiresPermissions("user_row_delById")
    @PostMapping(value = "/delById",name = "user_row_delById")
    public void delById(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.delById(ToolClient.getFormData(request)),response);
    }

    /**批量删除*/
    @RequiresPermissions("user_btn_delByKeys")
    @PostMapping(value = "/delByKeys",name = "user_btn_delByKeys")
    public void delByKeys(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.delByKeys(ToolClient.getFormData(request)),response);
    }

    /**获取数据*/
    @RequiresPermissions("user_btn_listData")
    @GetMapping(value = "/listData",name = "user_btn_listData")
    public void listData(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.listData(ToolClient.getFormData(request)),response);
    }

    /**获取角色数据*/
    @RequiresPermissions("user_btn_row_getAllotRole")
    @GetMapping(value = "/getAllotRole",name = "user_btn_row_getAllotRole")
    public void getAllotRole(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.getAllotRole(ToolClient.getFormData(request)),response);
    }

    /**保存分配角色*/
    @RequiresPermissions("user_btn_row_saveAllotRole")
    @PostMapping(value = "/saveAllotRole",name = "user_btn_row_saveAllotRole")
    public void saveAllotRole(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.saveAllotRole(ToolClient.getFormData(request)),response);
    }

    /**控制启禁用*/
    @RequiresPermissions("user_row_editEnabled")
    @PostMapping(value = "/editEnabled",name = "user_row_editEnabled")
    public void editEnabled(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.editEnabled(ToolClient.getFormData(request)),response);
    }

    /**根据指定userid获取菜单用于分配私有菜单*/
    @RequiresPermissions("user_row_getOwnMenu")
    @GetMapping(value = "/getOwnMenu",name = "user_row_getOwnMenu")
    public void getOwnMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.getOwnMenu(ToolClient.getFormData(request)).replaceAll("\"false\"","false").replaceAll("\"true\"","true"),response);
    }

    /**保存私有菜单(用户菜单)*/
    @RequiresPermissions("user_row_saveOwnMenu")
    @PostMapping(value = "/saveOwnMenu",name = "user_row_saveOwnMenu")
    public void saveOwnMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.saveOwnMenu(ToolClient.getFormData(request)),response);
    }

    /**查看指定userid权限菜单数据*/
    @RequiresPermissions("user_row_getMenuData")
    @GetMapping(value = "/getMenuData",name = "user_row_getMenuData")
    public void getMenuData(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(userService.getMenuData(ToolClient.getFormData(request)).replaceAll("\"false\"","false").replaceAll("\"true\"","true"),response);
    }

    @GetMapping(value = "/notAuthorized",name = "user_notAuthorized")
    public void notAuthorized(final HttpServletResponse response){
        ToolClient.responseJson(ToolClient.notAuthorized(),response);
    }
}