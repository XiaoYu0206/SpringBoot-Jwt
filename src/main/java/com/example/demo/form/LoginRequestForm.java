package com.example.demo.form;

import lombok.Data;

import java.io.Serializable;

@Data
public class LoginRequestForm implements Serializable {

    private String username;

    private String password;

}
