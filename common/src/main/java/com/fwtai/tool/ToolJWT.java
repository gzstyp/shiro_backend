package com.fwtai.tool;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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
    private final static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsznNs84d1oZtgVw3tN4YgXh2XZ957/nmykpha/OghcqioCZT/H9QM/NQnlUY7x0hPkF2CvTMmkjspWY/6UE89vvASGhtoz0BuTe/Cn3OUS0ddefMhlyOrN8iXiGz1v1KzlmOEN0bR1PyhF64WhGbBxFw54DP/LPrGp3azygvn6SEpMH2FaRwKoJBpsESHxbrnAwv8/YJOnK2TIlohN3pc8KyJIj6vgpdQXs/38cAugkXe3arpYXqCW83fjLz8sqMGcE/joylLeO7EGeI0ixeBFpLJ0TyrAqu/smpg+qfYj3RQfGj9RmJVHJdMyDfU4kLRhEXEMfgo5Fwwt19Fm82aQIDAQAB";
    /**2048的密钥位的私钥*/
    private final static String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzOc2zzh3Whm2BXDe03hiBeHZdn3nv+ebKSmFr86CFyqKgJlP8f1Az81CeVRjvHSE+QXYK9MyaSOylZj/pQTz2+8BIaG2jPQG5N78Kfc5RLR1158yGXI6s3yJeIbPW/UrOWY4Q3RtHU/KEXrhaEZsHEXDngM/8s+sandrPKC+fpISkwfYVpHAqgkGmwRIfFuucDC/z9gk6crZMiWiE3elzwrIkiPq+Cl1Bez/fxwC6CRd7dqulheoJbzd+MvPyyowZwT+OjKUt47sQZ4jSLF4EWksnRPKsCq7+yamD6p9iPdFB8aP1GYlUcl0zIN9TiQtGERcQx+CjkXDC3X0WbzZpAgMBAAECggEAZrovCWyO9bM/ePIei/DxIuSlE6yg+8fFXRWdGX8e9xDafej6IrPmiKBiCR7Fl+iecUycGFOQIq7B1VvyLgRSqU5LPDV/Ah2pqzwkqCLL6wNs63PdavYKYVPUIxg2OHgeNIBoSYoyZIPdcbnI+Pc2YKrCiC7xB+soSq1ICY0DHwD662+/6xBivWDLySB+HjUU0KTvIAfm0qDYiVkJK6/bqVK8pVALz1dhDnVg+oBFmhOyNa/EuC70A3fySVUeOHKRdls+lzH4lJxxVhVsXJJ61hKCHUuZWXIgTZOldw7myAOkhRf9nDcFW4mNDm29gK9KeZs7CZ6Ro+M3eUP2USUawQKBgQDqVZyLLE1Lz80B5tNAl6joPiesL18B8FBGb8JsMSEwKT1wkena7jgDgWqYf4nQTwT9Sslj4kxhs1XW/b64R0R8nrQCgSMuNKHkydQDSgV44g86fVc6IBAw8iDG7PoT0nXcLIvoynBKPPxg+e8lDI2xN5y3k0e526RYHRWsyVhUlQKBgQDDy9fW85aQZsmTwJvMP9mdl8gAjuverpcksPWjSmFFPJMCVDDuXbdcPuPQkRuhlg0Kq3Fti6S+0BaqjxHMvOIM6XNSPoDv78OAD9ip9w3Y1fugtSzkUcgajUz4bw44C0DFSqIKFVbiAhGw7liZ4C2uAvdoevRW2eJ/FoFLZn/xhQKBgQDntqgI5lG4eU5aZwjVgiG/JFbOaDkmDZ8TR0eU/C+5E85xFZeMqKoyrTHegZ6goMJqRB1H62lj4pUq9dY1GiOapsORBmjnM5wyQ3Cln/gxRDeSuoYaL8JS49mNWp8eIqnwgQwHsMXAYvWcXwgeNn+VkUwiKjxuh8XGa1wXczEo0QKBgGZ1alqCl7yy/TNDbIQCuacdQT0BjW63IELEE5bCmoo3u5pRYlWqVwR/qImBFduGAQcfVjkEBU8Q53uTaLYh9YzaMU3NhX2Jk12VbUTsEqPwvj+H75j/Lt6uKKQswV0Ujm1vs8HhDtkwSf+zikvjoyPXS46yIOC+HidxKHHDjppdAoGBALoEJLaLgkPPTiwfobl3wWpbdgyik3/hz+LMh+L/4YhbWxNi5Ik1MdJIoqawKRk0sElX/DWB97ekq9J5Brxtg4HZWTFrTfBlXJL3Fu26XCkdZRbFPenSmUvpQzhfoGr8ZYT6FNB6WB5lT1uKN0qdxS3AaKj9NNMTbxomuVAguRYH";

    /**java生成的私钥是pkcs8格式的公钥是x.509格式*/
    private final static PublicKey getPublicKey(){
        try {
            final byte[] keyBytes = Base64.getDecoder().decode(publicKey);
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
            final byte[] keyBytes = Base64.getDecoder().decode(privateKey);
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