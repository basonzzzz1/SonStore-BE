package com.example.ecommerce_supper.payload.request;

public class BannerRequest {
   private String username;

    public BannerRequest() {
    }

    public BannerRequest(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}