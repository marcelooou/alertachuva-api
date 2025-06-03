package com.fiap.alertachuva.auth;

import com.fiap.alertachuva.entity.User;
import com.fiap.alertachuva.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final String SECRET_KEY = "fiap-secret";

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User user) {
        User u = userRepository.findByUsername(user.getUsername())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!u.getPassword().equals(user.getPassword())) {
            throw new RuntimeException("Senha inválida");
        }

        String token = Jwts.builder()
                .setSubject(u.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hora
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();

        return Map.of("token", token);
    }
}
