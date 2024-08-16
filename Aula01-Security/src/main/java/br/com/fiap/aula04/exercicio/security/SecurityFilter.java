package br.com.fiap.aula04.exercicio.security;

import br.com.fiap.aula04.exercicio.repository.UsuarioRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.antlr.v4.runtime.Token;
import br.com.fiap.aula04.exercicio.service.TokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class SecurityFilter extends OncePerRequestFilter {

    private TokenService tokenService;
    private UsuarioRepository usuarioRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Recuperar o token jwt da requisição
        String token = request.getHeader("Authorization");
        //Validar o token
        if (token != null){
            //Tirar a palavra "Beare" do token
            token = token.replace("Bearer", "");
            //Recuperar o usuario do token
            var subject = tokenService.getSubject(token);
            //Pesqueisar o usuario no banco de dados
            var usuario = usuarioRepository.findByLogin(subject);
            //Criar o Token de autenticacao
            var autenticationToken = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());

            //Setar a autenticacao no contexto
            SecurityContextHolder.getContext().setAuthentication(autenticationToken);


        }

        filterChain.doFilter(request, response);


    }
}
