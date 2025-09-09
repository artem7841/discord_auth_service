package com.example.auth_service.model;


import lombok.Data;

@Data
public class SignupRequest {
    private String name;
    private String email;
    private String password;
}
