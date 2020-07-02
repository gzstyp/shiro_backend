package com.fwtai.tool;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sun.misc.BASE64Decoder;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * jwt(JSON Web Token)令牌工具类
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-02-12 23:53
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
public final class ToolJWT implements Serializable{

    //如设置Token过期时间15分钟，建议更换时间设置为Token前5分钟,通过try catch 获取过期
    private final static long access_token = 1000 * 60 * 45;//当 refreshToken 已过期了，再判断 accessToken 是否已过期,

    /**一般更换新的accessToken小于5分钟则提示需要更换新的accessToken*/
    private final static long refresh_token = 1000 * 60 * 40;//仅做token的是否需要更换新的accessToken标识,小于5分钟则提示需要更换新的accessToken

    private final static String issuer = "贵州富翁泰科技有限责任公司";//jwt签发者

    /**2048的密钥位的公钥*/
    private final static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgHN6mDgv+3RQUiS9xRqevGkTdimPmNGekBvsRXxWc/4T0gniGDLM+czdqBDirWtnQM2BrAtqOZJCU3gjbUwbtc4fPjM8YJPRLjb5DE2kouzveoykas/OqtfcdWPm8oxW1moGglpL0ZBvcMK0SCdTuhsISFhBkAdz8QPL22UatuapjEq7QZXcbQKtLXhKxJiKDFSL1LAL32WZO9T452zQGIJSlPdu77ngjEs2ekmOKKFV8LmJyocwzR/JWj/YWdCqvGmzqYXMywFCWB+IzyJCXX8lgGnhPnh0AX9vzkGNth0qg/UWEYyY72zSfPZLnPo976+KXPZd2VqT1+4sJwM6ZwIDAQAB";
    /**2048的密钥位的私钥*/
    private final static String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCAc3qYOC/7dFBSJL3FGp68aRN2KY+Y0Z6QG+xFfFZz/hPSCeIYMsz5zN2oEOKta2dAzYGsC2o5kkJTeCNtTBu1zh8+Mzxgk9EuNvkMTaSi7O96jKRqz86q19x1Y+byjFbWagaCWkvRkG9wwrRIJ1O6GwhIWEGQB3PxA8vbZRq25qmMSrtBldxtAq0teErEmIoMVIvUsAvfZZk71PjnbNAYglKU927vueCMSzZ6SY4ooVXwuYnKhzDNH8laP9hZ0Kq8abOphczLAUJYH4jPIkJdfyWAaeE+eHQBf2/OQY22HSqD9RYRjJjvbNJ89kuc+j3vr4pc9l3ZWpPX7iwnAzpnAgMBAAECggEAPcFHK2+4AdiF1Tg81EpcDpEl/iU1GG+PIBGMokuI9PMubEi8Ho4t5dsMpgSYNm/wkEM9GI3UYCFlKeQUhDOXDu0uMCVJ3dSzONjNG5Eomfv3lp+PXJrT7WciYn3JRssZ5LPMtVbcJMCgE0JIknf11P+yF7X2r1wl7bW5iJ0vHsdMys8B621YCTYwll3fHSMzql0AH2e2h2ADzT5xz7g4eRisc8JYmCBweK5t8g64EBVh6oe00SDTDcCuBf2GcIYATvHli4v+JxkX3bHT4B/92kyjXJfa0/mZb1Vxs65K/JAL6JcKmq5NU3UbNctJa+n3uOBXuzY1eVYSJ+RT+XC04QKBgQDdyij2OX3LR1eg6u75Qnx96QOnyXiWNUuUSiDCtgNCfdUx4GveJC1zXsb4DYcqoQSAjlFcnak+X6vSjKZOxIo/ldHM25lIRL8PXZIjbidTKIacdJzOrJwEfjDws4Mu1MP3CWT5WBYGThRq3k4m1RNJww2i1v+xEPjKmjlogRuUrQKBgQCUQ6UP/RUleJ8rv2FU7cMfK4hx7yNkQIWh6EsVOINjifZN8PjLTpQwZO/9z796pZDK2u9hZT2Xket3nDQzLquEsBTkMVPzSm7MD+QPVhgJvZRK9jH0zStl+6Eq0tq4nwZCEOHros20UXD8P+609LlkZ7dhucjo6S2H3kRRAd+Z4wKBgQCzWTrugWcb7sEJu3Er13vcRYVTNTRyIv7PF3KOgaj5J9Ay2QvhQtgOJ2I2TJo0+qgtXOimQEgPzEWhqWMC5yP0by6MvjehnRXzUvNN+1GJiYfxFMuIxUQUzga9XiyCvkMJjWs9xuFoj9Mq6EHCXSOPzk9Ekx+JC/RjwXsS6vRmsQKBgANvJa2fIRRDHPy4bBq5fyGDsp9g+KLj07SSWtrc+j4d/fSENl8PLOOKEv0ACOFgYGAyfgT1gV23ZYrZtWPSGurx4Sn/8n/aI4Lag1/PkLL5DyxFU5bmAbFVCMCjLanFFTIGjhUVKkqY8FMHcBIE8R5gQKEk2oB6ljFldpOhxXodAoGAC7Dy8rohc7k4BMKp2yaUT9wH6ZlgJyWX4yPs5DCONnoR0PN9U3vLjnY8CY9iRPYRWNZszBuNZlMPEjX2EnPJPORfOKq10r1LNFgrKK831L8Nsyw3WLuBHsQ1FZZB7ZavKHm/8Q+2TBpU2vUbFxonZ/Pv3PcfUoIZuQE8t0WomEw=";

    /**java生成的私钥是pkcs8格式的公钥是x.509格式*/
    private final static PublicKey getPublicKey(){
        try {
            final byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(publicKey);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private final static PrivateKey getPrivateKey(){
        try {
            final byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(privateKey);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // setSubject 不能和s etClaims() 同时使用,如果用不到 userId() 的话可以把setId的值设为 userName !!!
    private final static String createToken(final String userId,final Object value,final long expiryDate){
        final ExecutorService threadPool = Executors.newCachedThreadPool();
        final Future<String> future = threadPool.submit(new Callable<String>(){
            @Override
            public String call() throws Exception{
                final Date date = new Date();
                final JwtBuilder builder = Jwts.builder().setIssuer(issuer).signWith(SignatureAlgorithm.RS384,getPrivateKey()).setId(userId).setIssuedAt(date).claim(userId,value).setExpiration(new Date(date.getTime() + expiryDate));
                return builder.compact();
            }
        });
        try {
            return future.get();
        } catch (Exception e) {
            threadPool.shutdown();
            return null;
        }
    }

    public final static Claims parser(final String token){
        return Jwts.parser().requireIssuer(issuer).setSigningKey(getPublicKey()).parseClaimsJws(token).getBody();
    }

    /**
     * 验证token是否已失效,返回true已失效,否则有效
     * @param token
     * @作者 田应平
     * @QQ 444141300
     * @创建时间 2020年2月24日 16:19:00
    */
    public final static boolean tokenExpired(final String token) {
        try {
            return parser(token).getExpiration().before(new Date());
        } catch (final ExpiredJwtException exp) {
            return true;
        }
    }

    /**仅作为是否需要刷新的accessToken标识,不做任何业务处理*/
    public final static String expireRefreshToken(final String userId){
        return createToken(userId,null,refresh_token);
    }

    /**生成带认证实体且有权限的token,最后个参数是含List<String>的角色信息,*/
    public final static String expireAccessToken(final String userId,final Object value){
        return createToken(userId,value,access_token);
    }
}