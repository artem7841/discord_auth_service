package com.example.auth_service.model;


import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class UserInfo {
    private UUID id;
    private String name;
    private String email;
    private String avatar;
}
