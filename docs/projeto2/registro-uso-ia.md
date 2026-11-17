# Registro de uso de IA — Projeto 2 (CryptoLab)

Este registro atende ao item "Registro de utilização de IA" do enunciado e ao feedback do Projeto 1, que apontou documentação incompleta. Para cada uso, ele informa a ferramenta, a finalidade, o prompt, a resposta, o que foi aproveitado, o que foi descartado e como a informação foi validada.

## Ferramentas

- **Claude Code** (modelo Claude Opus 5.5), em terminal, com acesso ao repositório local. Apoiou a construção geral do projeto: planejamento, implementação, testes, revisão e redação.
- **Codex**, usado por um integrante da equipe para uma revisão cruzada independente (caso 12).
- Modo de trabalho: os requisitos do enunciado foram divididos em tarefas, cada uma desenvolvida com testes (TDD): cada funcionalidade começou com um teste que falhava. A equipe definiu os requisitos, revisou as entregas e decidiu o que adotar.

## Prompts principais

1. *"Eu tenho um trabalho de cybersegurança para continuar [...] te mandarei como contexto"*, acompanhado do PDF do Projeto 1, do relatório entregue, do repositório e do feedback do professor.
   **Resposta:** resumo do que já existia (10 achados, AES-GCM com chave única etc.) e lacunas do relatório (registro de IA, gestão de chaves, matriz de riscos, MFA/Zero Trust).
   **Aproveitado:** o diagnóstico de que a `MESSAGE_ENCRYPTION_KEY` cifrava todas as conversas diretamente, base da Tarefa 7.
2. *"Aula 26 - Projeto 2.pdf: especificação do projeto 2. Faça essa atividade: primeiro planeje ela inteira, depois execute seu plano até funcionar tudo e bater todos os requisitos."*
   **Resposta:** plano de 10 tarefas, com a lista de requisitos ("Global Constraints") copiada do PDF e uma seção de riscos não cobertos ("Review Focus").

## Usos, validação e correções

| # | Finalidade | Resposta da IA | Aproveitado | Descartado ou corrigido | Validação |
|---|---|---|---|---|---|
| 1 | Projeto da cifra | SPN com XOR, S-box e permutação dependentes da chave, e MixColumns | Estrutura da SBX-128 e do envelope encrypt-then-MAC | Não usar só XOR + permutação: sem camada linear não há difusão entre bytes (o SAC confirmou: 1 rodada tem desvio de 0,469) | Testes de *round-trip* (200 blocos), vetor fixo, adulteração de cada bit do envelope |
| 2 | Gestão de chaves | HKDF por finalidade, `key_id` e rotação | `cryptolab/keys.py` e mensagens v2 do SecureBoard | — | Testes: chaves distintas por *salt* e por finalidade; conversa A não abre conversa B; mensagens v1 ainda legíveis |
| 3 | Métrica de avalanche | Medir sobre 1 bloco, com IV/*salt* fixos | Avalanche sobre 15 bytes; SAC por número de rodadas (1, 2, 4, 10) | A medida em mensagens longas subestimava a difusão por causa do encadeamento CBC | Valores batem com a teoria: 1 rodada muda 1 byte (3,1%); 10 rodadas ≈ 50% |
| 4 | Contaminação do Isolation Forest | Valor inicial do plano: 0,02 | Ajustado para 0,002 | 0,02 gerava cerca de 4.000 alertas para cerca de 300 janelas anômalas (precisão < 10%) | Precisão e recall medidos contra os rótulos da simulação |
| 5 | Teste do dashboard | Teste de upload que embutia `get_data(as_text=True)` de um PNG na mensagem de erro | — | Erro da própria IA: decodificar PNG como UTF-8 quebrava o teste antes da asserção | Corrigido para `hide.data[:300]`; o teste passou pelo motivo certo |
| 6 | Métrica de adulteração da esteganografia | A execução completa registrou `tamper_detected = False` | Novo helper `flip_payload_bit` e teste dedicado | A métrica antiga alterava o pixel (0,0), que, com a ordem embaralhada, não carregava o segredo. Não era falha de segurança, era teste errado | Novo teste altera bits do payload (cabeçalho, corpo e tag): 3 de 3 rejeitados |
| 7 | *Recall* zero de `file_tamper` no IF | Explicação: evento único em janela normal não se isola | Detector híbrido (IF ∪ regras) | A ideia de "ajustar o IF até pegar tudo", que seria sobreajuste ao gerador sintético | *Recall* por família: IF 0%, regras 100%, híbrido 100% |
| 8 | Episódios de `file_tamper` | O gerador criou 2.020 episódios (orçamento por família) | Limite de max(3, n/50k) episódios | Volume irrealista para alterações em arquivos sensíveis | Execução com 1M: 20 episódios |
| 9 | Revisão final independente (nova sessão de IA, sem contexto da implementação) | 1 achado importante e 6 menores | Correções: o dashboard e a esteganografia não quebram mais (500) quando outro processo segura o DuckDB; avalanche medida só no texto cifrado, porque a tag HMAC mascarava a difusão | Achados menores ficaram como pendências documentadas | Testes que reproduzem cada achado falharam antes e passaram depois |
| 10 | Relatório e slides | Estrutura e redação | Texto e organização | Toda afirmação sem número foi trocada por valor de `evidencias/results.json` e `detection.json` | Conferência manual de cada número com os JSONs da execução de 11/11/2026 |
| 11 | Revisão "com olhar de professor" contra o enunciado (Aula 26) e o feedback do Projeto 1. Prompt: *"Revise se tudo que a professora solicitou está sendo contemplado; caso não esteja, corrija tudo e deixe pronto"* | Lacunas: a ordem da esteganografia usava a **mesma chave para todas as imagens** (o padrão criticado no P1); a entrada "arquivos" do diagrama não existia; *file_tamper* só existia nos dados sintéticos; o botão rápido sobrescrevia os resultados do relatório; faltava `MAX_CONTENT_LENGTH`; pseudônimos diferentes entre web e importação; referências cruzadas erradas e seções do relatório sem os nomes da Parte 5 | Salt por imagem na esteganografia; cifragem de arquivos; verificação SHA-256 com linha de base assinada por HMAC; execução ao vivo separada; limite de 5 MB; pseudônimo único; relatório reorganizado pelos 5 itens da Parte 5 | A sugestão de "documentar como pendência" foi descartada: tudo foi corrigido | 22 testes novos, cada um falhando antes da correção; suíte de 353 testes passando num clone limpo; pipeline completo reexecutado e números do relatório conferidos com `evidencias/results.json` (cifra, ataques e IA idênticos à execução anterior) |
| 12 | Revisão cruzada com outra IA (**Codex**), seguida de verificação pela equipe, com apoio do **Claude Code**. Prompt: *"Revise o PR, o relatório e os slides contra o enunciado"* | Seis apontamentos: chaves fracas na SBX-128 (difusão presa numa coluna); IA treinada e avaliada nos mesmos dados; híbrido com só 1 acerto a mais e 176 falsos positivos; exagero em "nenhuma chave cifra mais de um objeto"; arquivo de 4 MB cifrado que não decifrava; nome original no download do `.sbx` | Correção da permutação no *key schedule*; folga do envelope no limite de decifragem; download com nome aleatório; textos corrigidos no relatório e nos slides | Nenhum apontamento foi aceito sem reprodução. A avaliação da IA não foi refeita: foi declarada exploratória, com o limite explicado | Chaves fracas medidas em 20.000 chaves (0,18%; pior avalanche 10,9% → 34,4% após a correção); 4 testes novos falhando antes e passando depois; avalanche recalculada no `results.json`; suíte de 357 testes passando |

## Princípio

Nenhuma resposta da IA foi aceita sem execução. Os casos 5, 6, 8, 11 e 12 são erros reais (da IA ou do projeto desenvolvido com o apoio dela), encontrados pela evidência (teste ou execução completa) e corrigidos antes da entrega. A responsabilidade pela adoção, pelo descarte e pela validação ficou com a equipe.
