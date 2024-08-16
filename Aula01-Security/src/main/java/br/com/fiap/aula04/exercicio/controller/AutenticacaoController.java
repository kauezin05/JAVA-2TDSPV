package br.com.fiap.aula04.exercicio.controller;

import br.com.fiap.aula04.exercicio.dto.autenticacao.AutenticacaoDto;
import br.com.fiap.aula04.exercicio.dto.autenticacao.DadosTokenJwtDto;
import br.com.fiap.aula04.exercicio.model.Usuario;
import br.com.fiap.aula04.exercicio.service.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("login")
public class AutenticacaoController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    @PostMapping
    public ResponseEntity<DadosTokenJwtDto> login(
            @RequestBody @Valid AutenticacaoDto dto){
        var usuario = new UsernamePasswordAuthenticationToken(dto.login(), dto.senha());
        var authenticate = authenticationManager.authenticate(usuario);
        var token = tokenService.gerarToken((Usuario) authenticate.getPrincipal());
        return ResponseEntity.ok(new DadosTokenJwtDto(token));
    }

}
