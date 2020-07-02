package com.fwtai.web.controller;

import com.fwtai.service.web.RoleService;
import com.fwtai.tool.ToolClient;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 角色管理接口入口
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-03-13 17:14
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
@RestController
@RequestMapping("/role")
public class RoleController{

    @Resource
    private RoleService roleService;

    /**添加*/
    @RequiresPermissions("role:btn:add")
    @PostMapping(value = "/add",name = "role:btn:add")
    public void add(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.add(ToolClient.getFormData(request)),response);
    }

    /**编辑*/
    @RequiresPermissions("role:row:edit")
    @PostMapping(value = "/edit",name = "role:row:edit")
    public void edit(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.edit(ToolClient.getFormData(request)),response);
    }

    /**删除-单行*/
    @RequiresPermissions("role:row:delById")
    @PostMapping(value = "/delById",name = "role:row:delById")
    public void delById(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.delById(ToolClient.getFormData(request)),response);
    }

    /**批量删除*/
    @RequiresPermissions("role:btn:delByKeys")
    @PostMapping(value = "/delByKeys",name = "role:btn:delByKeys")
    public void delByKeys(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.delByKeys(ToolClient.getFormData(request)),response);
    }

    /**获取数据*/
    @RequiresPermissions("role:btn:listData")
    @GetMapping(value = "/listData",name = "role:btn:listData")
    public void listData(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.listData(ToolClient.getFormData(request)),response);
    }

    /**行按钮清空菜单*/
    @RequiresPermissions("role:row:delEmptyMenu")
    @PostMapping(value = "/delEmptyMenu",name = "role:row:delEmptyMenu")
    public void delEmptyMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.delEmptyMenu(ToolClient.getFormData(request)),response);
    }

    /**获取角色菜单*/
    @RequiresPermissions("role:row:getRoleMenu")
    @GetMapping(value = "/getRoleMenu",name = "role:row:getRoleMenu")
    public void getRoleMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.getRoleMenu(ToolClient.getFormData(request)).replaceAll("\"false\"","false").replaceAll("\"true\"","true"),response);
    }

    /**保存角色菜单*/
    @RequiresPermissions("role:row:saveRoleMenu")
    @PostMapping(value = "/saveRoleMenu",name = "role:row:saveRoleMenu")
    public void saveRoleMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(roleService.saveRoleMenu(ToolClient.getFormData(request)),response);
    }

    @GetMapping(value = "/notAuthorized",name = "role:notAuthorized")
    public void notAuthorized(final HttpServletResponse response){
        ToolClient.responseJson(ToolClient.notAuthorized(),response);
    }
}