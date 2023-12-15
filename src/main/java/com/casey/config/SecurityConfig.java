package com.casey.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// AOP：拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 链式编程
    // 授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 首页所有人可以访问，功能页只有对应有权限的人才能访问
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        // 没有权限默认会到登录页面，需要开启登录页面
        // 自带的login页面，定制登录页面
        http.formLogin().loginPage("/toLogin")
                .usernameParameter("user_name").passwordParameter("pwd");
        // 防止网址攻击：get，post
        http.csrf().disable();  // 关闭 csrf
        // 注销
        http.logout().logoutSuccessUrl("/toLogin");
        // 开启记住我功能 cookie
        http.rememberMe().rememberMeParameter("remember");
    }
    // 认证，springboot2.1.x可以正常使用
    // 密码编码：PasswordEncoder
    // 在 Spring Security 5.0+ 新增了很多加密方式（MD5，Base64等等）
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 这些数据正常应该从数据库读取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("Casey").password(new BCryptPasswordEncoder().encode("123456"))
                .roles("vip1", "vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("root")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2");
    }
}
