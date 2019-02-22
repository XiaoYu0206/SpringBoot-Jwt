package com.example.demo.controller;

import com.example.demo.form.LoginRequestForm;
import com.example.demo.service.JwtUserDetailsServiceImpl;
import com.example.demo.user.JwtUser;
import com.example.demo.util.JwtTokenUtil;
import com.example.demo.vo.ResultVo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

@RestController
@RequestMapping("")
public class UserController {

    @Value("${jwt.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsServiceImpl userDetailsService;

    @RequestMapping(value = "/auth",method = RequestMethod.POST)
    public ResponseEntity<?> login(@RequestBody LoginRequestForm form){
        authenticate(form.getUsername(),form.getPassword());
        UserDetails userDetails = userDetailsService.loadUserByUsername(form.getUsername());
        final String token = jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new ResultVo(token));
    }

    /**
     * Authenticates the user. If something is wrong, an {@link AuthenticationException} will be thrown
     */
    private void authenticate(String username, String password) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new RuntimeException("User is disabled!", e);
        } catch (BadCredentialsException e) {
            throw new RuntimeException("Bad credentials!", e);
        }
    }

    @RequestMapping(value = "/refresh", method = RequestMethod.GET)
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
        String authToken = request.getHeader(tokenHeader);
        String token = authToken.substring(7);
        token = jwtTokenUtil.refreshToken(token);
        return ResponseEntity.ok(new ResultVo(token));
    }

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public ResponseEntity<?> hello() {
        return ResponseEntity.ok(new ResultVo("hello"));
    }

}
