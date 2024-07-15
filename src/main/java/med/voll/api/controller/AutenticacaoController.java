package med.voll.api.controller;

// Importações necessárias
import jakarta.validation.Valid;
import med.voll.api.domain.usuario.DadosAutenticacao;
import med.voll.api.domain.usuario.Usuario;
import med.voll.api.infra.security.DadosTokenJWT;
import med.voll.api.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController  // Indica que esta classe é um controlador REST
@RequestMapping("/login")  // Define o mapeamento de URL para este controlador
public class AutenticacaoController {

    // Injeção de dependência do AuthenticationManager
    @Autowired
    private AuthenticationManager manager;

    // Injeção de dependência do TokenService
    @Autowired
    private TokenService tokenService;

    // Mapeamento de uma requisição HTTP POST para a URL "/login"
    @PostMapping
    public ResponseEntity efetuarLogin(@RequestBody @Valid DadosAutenticacao dados) {
        // Criação de um token de autenticação com as credenciais fornecidas
        var authenticationToken = new UsernamePasswordAuthenticationToken(dados.login(), dados.senha());

        // Autenticação do token usando o AuthenticationManager
        var authentication = manager.authenticate(authenticationToken);

        // Geração de um token JWT a partir do usuário autenticado
        var tokenJWT = tokenService.gerarToken((Usuario) authentication.getPrincipal());

        // Retorna uma resposta HTTP 200 (OK) com o token JWT no corpo da resposta
        return ResponseEntity.ok(new DadosTokenJWT(tokenJWT));
    }
}

