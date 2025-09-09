package com.example.auth_service.model;


import lombok.Data;

@Data
public class SigninRequest {
    private String name;
    private String password;
}
