package com.example.auth_service.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;
    private String password;
    private String avatar;
}

//CREATE TABLE users (
//        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
//email TEXT UNIQUE NOT NULL,
//password_hash TEXT NOT NULL,
//name TEXT NOT NULL,
//created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
//avatar TEXT
//);