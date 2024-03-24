package com.example.ecommerce_supper.payload.request;

public class TokenRequest {
   private String token;

    public TokenRequest(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}