# Projeto de Agendamento e Cancelamento de Consultas com Spring Boot

Este projeto é um sistema de agendamento e cancelamento de consultas médicas, desenvolvido com Spring Boot, utilizando Java 22.

## Visão Geral

Este projeto foi desenvolvido como parte de um curso da Alura, onde aprendemos diversas funcionalidades do Spring Boot. A aplicação permite o agendamento e cancelamento de consultas médicas, além de fornecer documentação da API, testes automatizados e um processo de build para produção.

## Funcionalidades

- **Agendamento de Consultas:** Permite agendar consultas médicas.
- **Cancelamento de Consultas:** Funcionalidade implementada como desafio.
- **Documentação da API:** Utiliza SpringDoc e Swagger para documentação.
- **Testes Automatizados:** Testes de componentes (Repository e Controller) com banco de dados real (MySQL).
- **Build para Produção:** Geração de build via Maven, com configuração de variáveis de ambiente.

## Tecnologias Utilizadas

- Java 22
- Spring Boot
- SpringDoc
- Swagger
- Maven
- MySQL
- JUnit
- MockMvc
- JacksonTester

## Estrutura do Projeto

- **Aula 1:** 
  - Implementação de funcionalidades de agendamento e cancelamento de consultas.
  - Regras de negócio aplicadas na aplicação.
  - Uso de classe Service e seu controle.

- **Aula 2:** 
  - Isolamento de validações utilizando validadores injetados por polimorfismo com interface e List.
  - Aplicação de padrões de projeto e princípios do SOLID.

- **Aula 3:** 
  - Documentação da API com SpringDoc e Swagger.
  - Simulação de requisições e inclusão de cabeçalhos JWT na documentação.

- **Aula 4:** 
  - Testes automatizados focados em componentes do Spring (Repository e Controller).
  - Uso de banco de dados real (MySQL) para testes com profile específico.
  - Estratégia de teste de unidade para Controller utilizando MockMvc e JacksonTester.

- **Aula 5:** 
  - Geração do build da aplicação via Maven.
  - Configuração de arquivo properties para ambiente de produção.
  - Execução do projeto e simulação de deploy em ambiente de produção.

## Como Executar o Projeto

### Pré-requisitos

- Java 22 instalado
- Maven instalado
- MySQL instalado e configurado

### Passos para Executar

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/seu-repositorio.git
