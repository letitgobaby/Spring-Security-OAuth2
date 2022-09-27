package com.example.letitgobaby.utils;

import java.util.Date;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTBuilder {
  
  private String issuer = "letitgobaby";
  private Algorithm algorithm;
  private JWTVerifier verifier;
  private int accessTime;
  private int refreshTime;

  public JWTBuilder(String secret, int accessTime, int refreshTime) {
    this.algorithm = Algorithm.HMAC256(secret);
    this.accessTime = accessTime;
    this.refreshTime = refreshTime;
    this.verifier = JWT.require(algorithm).withIssuer(this.issuer).build(); 
  }

  public String accessGenerate(Object obj) throws Exception {
    return JWT.create()
      .withIssuer(this.issuer)
      .withClaim("userInfo", new ObjectMapper().convertValue(obj, Map.class))
      .withExpiresAt(setExpireTime(this.accessTime))
      .sign(this.algorithm);
  }

  public String refreshGenerate(Object obj) throws Exception {
    return JWT.create()
      .withIssuer(this.issuer)
      .withClaim("userInfo", new ObjectMapper().convertValue(obj, Map.class))
      .withExpiresAt(setExpireTime(this.refreshTime))
      .sign(this.algorithm);
  }

  public Boolean validate(String token) throws Exception {
    if (token == null) return null;
    
    DecodedJWT jwt = this.verifier.verify(token);
    String issuer = jwt.getIssuer();
    return issuer != null ? true : false;
  }

  public DecodedJWT decode(String token) {
    return JWT.decode(token);
  }

  public Claim getClaim(String token, String claimKey) {
    DecodedJWT decodedJWT = JWT.decode(token);
    return decodedJWT.getClaims().get(claimKey);
  }

  public void getExpiredTime() {

  }

  private Date setExpireTime(int timeProperty) {
    long expireDate = new Date().getTime() + (timeProperty * 60 * 1000);
    return new Date(expireDate);
  }

}
