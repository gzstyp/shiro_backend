package com.fwtai.web.controller;

import com.fwtai.service.web.MenuService;
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
 * 菜单管理接口入口
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-03-13 17:14
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
@RestController
@RequestMapping("/menu")
public class MenuController{

    @Resource
    private MenuService menuService;

    /**添加*/
    @RequiresPermissions("menu_btn_add")
    @PostMapping(value = "/add",name = "menu_btn_add")
    public void add(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.add(ToolClient.getFormData(request)),response);
    }

    /**编辑*/
    @RequiresPermissions("menu_row_edit")
    @PostMapping(value = "/edit",name = "menu_row_edit")
    public void edit(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.edit(ToolClient.getFormData(request)),response);
    }

    /**删除-单行*/
    @RequiresPermissions("menu_row_delById")
    @PostMapping(value = "/delById",name = "menu_row_delById")
    public void delById(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.delById(ToolClient.getFormData(request)),response);
    }

    /**获取数据*/
    @RequiresPermissions("menu_btn_listData")
    @GetMapping(value = "/listData",name = "menu_btn_listData")
    public void listData(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.listData(ToolClient.getFormData(request)),response);
    }

    /**获取详细信息*/
    @RequiresPermissions("menu_row_queryById")
    @GetMapping(value = "/queryById",name = "menu_row_queryById")
    public void queryById(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.queryById(ToolClient.getFormData(request)),response);
    }

    /**查询所有的菜单,用于添加或编辑菜单*/
    @RequiresPermissions("menu_btn_queryTreeMenu")
    @GetMapping(value = "/queryTreeMenu",name = "menu_btn_queryTreeMenu")
    public void queryTreeMenu(final HttpServletRequest request,final HttpServletResponse response){
        ToolClient.responseJson(menuService.queryTreeMenu(ToolClient.getFormData(request)),response);
    }

    @GetMapping(value = "/notAuthorized",name = "menu_notAuthorized")
    public void notAuthorized(final HttpServletResponse response){
        ToolClient.responseJson(ToolClient.notAuthorized(),response);
    }
}