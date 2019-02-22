package com.example.demo.exception;

import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;

public class MyUsernameNotfoundException extends AuthenticationException {

    public MyUsernameNotfoundException(String msg){
        super(msg);
    }
//
//    public MyUsernameNotfoundException(String msg,Throwable t){
//        super(msg,t);
//    }
}
