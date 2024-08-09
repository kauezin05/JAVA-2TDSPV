package br.com.fiap.aula04.exercicio.service;

import br.com.fiap.aula04.exercicio.model.Usuario;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Value;

import java.time.Duration;
import java.time.Instant;

public class TokenService {

    //Atributo que recupera a configuração no application.properties
    @Value("${token.api.password}")
    private String senhaToken;

    public String gerarToken(Usuario usuario){
        try {
            Algorithm algorithm = Algorithm.HMAC256(senhaToken);
            return JWT.create()
                    .withIssuer("FIAP")
                    .withSubject(usuario.getLogin())
                    .withExpiresAt(Instant.now().plus(Duration.ofMinutes(15)))
                    .sign(algorithm);
        } catch(JWTCreationException e){
            throw new RuntimeException("Não foi possível criar o token JWT");
        }
    }

}
