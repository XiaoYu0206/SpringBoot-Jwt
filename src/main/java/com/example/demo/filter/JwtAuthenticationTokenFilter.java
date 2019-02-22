package com.example.demo.filter;

import com.example.demo.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        //从请求头部获取token
        String authToken = httpServletRequest.getHeader(jwtTokenUtil.getHeader());
        //如果token不为空
        if(!StringUtils.isEmpty(authToken)){
            String token = authToken.substring(7);
            //根据token获得用户名
            String username = jwtTokenUtil.getUsernameFormToken(token);
            //如果用户名不为空 且 security上下文不存在授权信息，说明是请求刚进来，未经过其它拦截器
            if(null != username && SecurityContextHolder.getContext().getAuthentication() == null){
                //从存储中根据用户名获取一个用户
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                //验证token的合法性
                if(jwtTokenUtil.validateToken(token,userDetails)){
                    //将用户信息写入authentication，方便后续操作
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    //将authentication存入ThreadLocal，方便后续获取用户信息
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        //放行
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }
}
