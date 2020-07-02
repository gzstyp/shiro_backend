package com.fwtai.service.web;

import com.fwtai.auth.CustomizedToken;
import com.fwtai.bean.PageFormData;
import com.fwtai.config.ConfigFile;
import com.fwtai.config.LocalUserId;
import com.fwtai.core.UserDao;
import com.fwtai.entity.User;
import com.fwtai.service.AsyncService;
import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJWT;
import com.fwtai.tool.ToolSHA;
import com.fwtai.tool.ToolString;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.mybatis.spring.MyBatisSystemException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/**
 * 用户账号
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-03-13 17:24
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
@Service
public class UserService{

    @Resource
    private UserDao userDao;

    @Resource
    private MenuService menuService;

    @Resource
    private AsyncService asyncService;

    private String SUPER_KEY = "ffffffffddf9f1ffffffffff88888888";

    public String add(final PageFormData pageFormData){
        final String p_user_name = "user_name";
        final String p_user_password = "user_password";
        final String p_verify_password = "verify_password";
        final String validate = ToolClient.validateField(pageFormData,p_user_name,p_user_password,p_verify_password);
        if(validate != null)return validate;
        final String user_name = pageFormData.getString(p_user_name);
        final String password = pageFormData.getString(p_user_password);
        final String verify = pageFormData.getString(p_verify_password);
        if(!password.equals(verify)){
            return ToolClient.createJson(ConfigFile.code199,"输入的两次密码不一致");
        }
        final String exist = userDao.queryExistByUser(user_name);
        if(exist != null){
            return ToolClient.createJson(ConfigFile.code199,user_name+"用户账号已存在,换个试试");
        }
        pageFormData.remove(p_user_password);
        pageFormData.remove(p_verify_password);
        pageFormData.put("kid",ToolString.getIdsChar32());
        pageFormData.put("password",ToolSHA.encoder(password,user_name));
        final int rows = userDao.add(pageFormData);
        return ToolClient.executeRows(rows);
    }

    public String edit(final PageFormData pageFormData){
        final String p_user_name = "user_name";
        final String p_user_password = "user_password";
        final String p_verify_password = "verify_password";
        final String p_kid = "kid";
        final String validate = ToolClient.validateField(pageFormData,p_user_name,p_user_password,p_verify_password,p_kid);
        if(validate != null)return validate;
        final String user_name = pageFormData.getString(p_user_name);
        final String password = pageFormData.getString(p_user_password);
        final String verify = pageFormData.getString(p_verify_password);
        if(!password.equals(verify)){
            return ToolClient.createJson(ConfigFile.code199,"输入的两次密码不一致");
        }
        final String exist = userDao.queryExistByUser(user_name);
        if(exist == null){
            return ToolClient.createJson(ConfigFile.code199,user_name+"用户账号已不存在");
        }
        pageFormData.remove(p_user_password);
        pageFormData.remove(p_user_name);
        pageFormData.remove(p_verify_password);
        pageFormData.put("password",ToolSHA.encoder(password,user_name));
        final int rows = userDao.edit(pageFormData);
        return ToolClient.executeRows(rows);
    }

    public String getAllotRole(final PageFormData pageFormData){
        final String userId = pageFormData.getString("userId");
        return ToolClient.queryJson(userDao.getAllotRole(userId));
    }

    public List<String> getPermissions(final String userId){
        return userDao.getPermissions(userId);
    }

    public List<String> getRoles(final String userId){
        return userDao.getRoles(userId);
    }

    //shiro认证(根据用户和密码获取用户id)
    public User queryLogin(final HashMap<String,String> params){
        return userDao.queryLogin(params);
    }

    public User queryUser(final String userName){
        return userDao.queryUser(userName);
    }

    public void updateErrors(final String userName){
        userDao.updateErrors(userName);
    }

    public void updateLoginTime(final String userName){
        userDao.updateLoginTime(userName);
    }

    public String delById(final PageFormData pageFormData){
        final String p_kid = "id";
        final String validate = ToolClient.validateField(pageFormData,p_kid);
        if(validate != null)return validate;
        final String kid = pageFormData.getString(p_kid);
        if(SUPER_KEY.equals(kid)){
            return ToolClient.createJson(ConfigFile.code204,ConfigFile.KEY_SUPER+"账号不能删除");
        }
        final String user_name = userDao.queryExistById(kid);//查询是否存在
        if(user_name == null){
            return ToolClient.createJson(ConfigFile.code199,"用户账号已不存在");
        }
        final int rows = userDao.delById(kid);
        return ToolClient.executeRows(rows);
    }

    //批量分配角色
    public String saveAllotRole(final PageFormData pageFormData){
        final String p_type = "type";
        final String validate = ToolClient.validateField(pageFormData,p_type);
        if(validate != null)return validate;
        final String fieldInteger = ToolClient.validateInteger(pageFormData,p_type);
        if(fieldInteger != null)return fieldInteger;
        final int type = pageFormData.getInteger(p_type);
        if(type == 1){
            final String userId = pageFormData.getString("userId");
            final String kids = pageFormData.getString("kids");
            if(userId == null){
                return ToolClient.jsonValidateField();
            }
            final String exist_key = userDao.queryExistById(userId);//查询是否存在
            if(exist_key == null){
                return ToolClient.createJson(ConfigFile.code199,"用户账号已不存在");
            }
            final ArrayList<String> listRoles = ToolString.keysToList(kids);
            if(listRoles == null || listRoles.size() <= 0){
                final int rows = userDao.delAllotRole(userId);//清空
                return ToolClient.executeRows(rows);
            }else{
                final ArrayList<HashMap<String,String>> lists = new ArrayList<HashMap<String,String>>();
                final Iterator<String> iterator = listRoles.iterator();
                while(iterator.hasNext()){
                    final HashMap<String,String> map = new HashMap<String,String>();
                    map.put("role_id",iterator.next());
                    map.put("user_id",userId);
                    lists.add(map);
                }
                final int rows = userDao.saveAllotRole(userId,lists);//清空之前的角色,重新分配角色
                return ToolClient.executeRows(rows);
            }
        }
        if(type == 2){
            final String userIds = pageFormData.getString("userIds");
            final String kids = pageFormData.getString("kids");
            if(userIds == null){
                return ToolClient.createJson(ConfigFile.code199,"请选择要分配角色的账号");
            }
            final ArrayList<String> listUserIds = ToolString.keysToList(userIds);
            final ArrayList<String> listRoles = ToolString.keysToList(kids);
            if(listRoles == null || listRoles.size() <= 0){
                final int rows = userDao.delBatchUserRole(listUserIds);
                return ToolClient.executeRows(rows);
            }else{
                final ArrayList<HashMap<String,String>> listMaps = new ArrayList<HashMap<String,String>>();
                final Iterator<String> iteratorUser = listUserIds.iterator();
                while(iteratorUser.hasNext()){
                    final Iterator<String> iteratorRoles = listRoles.iterator();
                    final String uid = iteratorUser.next();
                    while(iteratorRoles.hasNext()){
                        final HashMap<String,String> map = new HashMap<String,String>();
                        map.put("role_id",iteratorRoles.next());
                        map.put("user_id",uid);
                        listMaps.add(map);
                    }
                }
                final int rows = userDao.saveBatchUserRole(listUserIds,listMaps);
                return ToolClient.executeRows(rows);
            }
        }
        return ToolClient.jsonValidateField();
    }

    public String saveOwnMenu(final PageFormData pageFormData){
        final String p_userId = "userId";
        final String validate = ToolClient.validateField(pageFormData,p_userId);
        if(validate != null)return validate;
        final String kids = pageFormData.getString("kids");
        final String userId = pageFormData.getString(p_userId);
        final ArrayList<String> listMenus = ToolString.keysToList(kids);
        if(listMenus == null || listMenus.size() <= 0){
            final int rows = userDao.delOwnMenu(userId);
            return ToolClient.executeRows(rows,"操作成功","未做任何操作,因为暂无私有菜单");
        }else{
            final ArrayList<HashMap<String,String>> listMaps = new ArrayList<HashMap<String,String>>();
            final Iterator<String> iterator = listMenus.iterator();
            while(iterator.hasNext()){
                final HashMap<String,String> map = new HashMap<String,String>();
                map.put("menu_id",iterator.next());
                map.put("user_id",userId);
                listMaps.add(map);
            }
            final int rows = userDao.saveOwnMenu(userId,listMaps);
            return ToolClient.executeRows(rows);
        }
    }

    public String delByKeys(final PageFormData pageFormData){
        final String p_ids = "ids";
        final String validate = ToolClient.validateField(pageFormData,p_ids);
        if(validate != null)return validate;
        final String ids = pageFormData.getString(p_ids);
        final ArrayList<String> lists = ToolString.keysToList(ids);
        if(lists.contains(SUPER_KEY)){
            lists.remove(SUPER_KEY);
        }
        if(lists == null || lists.size() <= 0){
            return ToolClient.createJson(ConfigFile.code199,"请选择要删除的数据");
        }
        final int rows = userDao.delByKeys(lists);
        return ToolClient.executeRows(rows,"操作成功","用户已不存在,刷新重试");
    }

    public String editEnabled(final PageFormData pageFormData){
        final String p_disable = "disable";
        final String p_enabled = "enabled";
        final String p_userId = "userId";
        final String validate = ToolClient.validateField(pageFormData,p_disable,p_enabled,p_userId);
        if(validate != null)return validate;
        final String fieldInteger = ToolClient.validateInteger(pageFormData,p_disable,p_enabled);
        if(fieldInteger != null)return fieldInteger;
        final String kid = pageFormData.getString(p_userId);
        if(SUPER_KEY.equals(kid)){
            return ToolClient.createJson(ConfigFile.code204,"不能操作"+ConfigFile.KEY_SUPER+"账号");
        }
        final String user_name = userDao.queryExistById(pageFormData.getString(p_userId));//查询是否存在
        if(user_name == null){
            return ToolClient.createJson(ConfigFile.code199,"用户账号已不存在");
        }
        final int rows = userDao.editEnabled(pageFormData);
        return ToolClient.executeRows(rows);
    }

    public String login(final HttpServletRequest request){
        final HashMap<String,String> params = ToolClient.getFormParams(request);
        final String p_user_name = "userName";
        final String p_user_password = "password";
        final String validate = ToolClient.validateField(params,p_user_name,p_user_password);
        if(validate != null)return validate;
        final String userName = params.get(p_user_name);
        final String userPassword = params.get(p_user_password);
        final Subject subject = SecurityUtils.getSubject();
        final CustomizedToken token = new CustomizedToken(userName,userPassword,"PasswordRealm");//指定要认证的类名称,此处是com.fwtai.auth.PasswordRealm,是在类ShiroConfiguration的方法securityManager注入添加的
        try {
            subject.login(token);
            final User user = (User) subject.getPrincipals().getPrimaryPrincipal();
            final String userId = user.getKid();
            asyncService.updateLogin(userId);
            final HashMap<String,String> result = buildToken(userId,getRoles(userId));
            result.put("userName",userName);
            result.put("menuData",menuService.getMenuData(userId));
            return ToolClient.queryJson(result);
        } catch (final Exception e){
            if(e instanceof UnknownAccountException){
                return ToolClient.createJsonFail(e.getMessage());
            }else if(e instanceof ExcessiveAttemptsException){
                return ToolClient.createJson(ConfigFile.code198,e.getMessage());
            }else if(e instanceof MyBatisSystemException){
                return ToolClient.createJsonFail("连接服务器超时,请重试……");
            }
            return ToolClient.createJsonFail("登录失败,账号或密码错误");
        }
    }

    public String logout(){
        try {
            final Subject subject = SecurityUtils.getSubject();
            subject.logout();
        } catch (Exception e){
        }
        return ToolClient.createJsonSuccess("操作成功");
    }

    public String listData(PageFormData pageFormData){
        final String p_iColumns = "iColumns";
        final String validate = ToolClient.validateField(pageFormData,p_iColumns);
        if(validate != null)return validate;
        final String fieldInteger = ToolClient.validateInteger(pageFormData,p_iColumns);
        if(fieldInteger != null)return fieldInteger;
        try {
            pageFormData = ToolClient.dataTableMysql(pageFormData);
            if(pageFormData == null)return ToolClient.jsonValidateField();
            final String userId = LocalUserId.get();
            final String loginUser = userDao.queryExistById(userId);
            if(!loginUser.equals(ConfigFile.KEY_SUPER)){
                pageFormData.put("keySuper",loginUser);
                pageFormData.put("userId",userId);
            }
            final HashMap<String,Object> map = userDao.listData(pageFormData);
            return ToolClient.dataTableOK((List<Object>)map.get(ConfigFile.rows),map.get(ConfigFile.total),(List<String>)map.get(ConfigFile.permissions),pageFormData.get("sEcho"));
        } catch (Exception e){
            e.printStackTrace();
            return ToolClient.dataTableException(pageFormData.get("sEcho"));
        }
    }

    //根据指定userid获取菜单用于分配私有菜单
    public String getOwnMenu(final PageFormData pageFormData){
        final String p_userId = "userId";
        final String validate = ToolClient.validateField(pageFormData,p_userId);
        if(validate != null)return validate;
        final String userId = pageFormData.getString(p_userId);
        return ToolClient.queryJson(userDao.getOwnMenu(userId));
    }

    //查看指定userid权限菜单数据
    public String getMenuData(final PageFormData pageFormData){
        final String p_userId = "userId";
        final String validate = ToolClient.validateField(pageFormData,p_userId);
        if(validate != null)return validate;
        final String userId = pageFormData.getString(p_userId);
        return ToolClient.queryJson(userDao.getMenuData(userId));
    }

    //仅保存userId,userName,roles 即可
    public HashMap<String,String> buildToken(final String userId,final List<String> permissionRole){
        final HashMap<String,String> token = new HashMap<>(2);
        final String refresh_token = ToolJWT.expireRefreshToken(userId);
        final String access_token = ToolJWT.expireAccessToken(userId,permissionRole);
        token.put(ConfigFile.ACCESS_TOKEN,access_token);
        token.put(ConfigFile.REFRESH_TOKEN,refresh_token);
        return token;
    }
}