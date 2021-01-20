package com.warning.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Configuration
public class SecurityConfigTest extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 获取PasswordEncoder的实现类,进行秘密加密
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String password = passwordEncoder.encode("1234");
        // 设置用户名和密码
        auth.inMemoryAuthentication().withUser("Timmy").password(password).roles("admin");
    }
    // 把PasswordEncoder的实现类放入Spring容器中
    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
    }
}
