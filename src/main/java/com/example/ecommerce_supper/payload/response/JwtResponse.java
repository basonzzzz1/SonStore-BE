package com.example.ecommerce_supper.payload.response;

import java.util.List;

public class JwtResponse {
  private String token;
  private String type = "Bearer";
  private Long id;
  private String username;
  private String phone;
  private boolean isBanner;
  private String image;
  private List<String> roles;

  public JwtResponse(String accessToken, Long id, String username, String phone,boolean isBanner,String image, List<String> roles) {
    this.token = accessToken;
    this.id = id;
    this.username = username;
    this.phone = phone;
    this.isBanner = isBanner;
    this.image = image;
    this.roles = roles;
  }

  public String getAccessToken() {
    return token;
  }

  public void setAccessToken(String accessToken) {
    this.token = accessToken;
  }

  public String getTokenType() {
    return type;
  }

  public void setTokenType(String tokenType) {
    this.type = tokenType;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getToken() {
    return token;
  }

  public void setToken(String token) {
    this.token = token;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public void setRoles(List<String> roles) {
    this.roles = roles;
  }

  public String getPhone() {
    return phone;
  }

  public void setPhone(String phone) {
    this.phone = phone;
  }

  public boolean isBanner() {
    return isBanner;
  }

  public void setBanner(boolean banner) {
    isBanner = banner;
  }

  public String getImage() {
    return image;
  }

  public void setImage(String image) {
    this.image = image;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public List<String> getRoles() {
    return roles;
  }
}
