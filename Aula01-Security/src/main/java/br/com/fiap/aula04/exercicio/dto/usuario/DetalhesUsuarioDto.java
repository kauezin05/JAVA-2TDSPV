package br.com.fiap.aula04.exercicio.dto.usuario;

import br.com.fiap.aula04.exercicio.model.Usuario;

public record DetalhesUsuarioDto(Long id, String login) {

    public DetalhesUsuarioDto(Usuario usuario){
        this(usuario.getId(), usuario.getLogin());
    }

}
