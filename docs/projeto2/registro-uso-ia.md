# Registro de uso de IA — Projeto 2 (CryptoLab)

Este registro atende ao item "Registro de utilização de IA" do enunciado e ao feedback do Projeto 1, que apontou documentação incompleta. Para cada uso, ele informa a ferramenta, a finalidade, o prompt, a resposta, o que foi aproveitado, o que foi descartado e como a informação foi validada.

## Ferramenta

- **Claude Code** (modelo Claude Opus 5.5), em terminal, com acesso ao repositório local.
- Modo de trabalho: planejamento escrito (`docs/superpowers/plans/2026-11-11-projeto2-cryptolab.md`) seguido de execução tarefa a tarefa com TDD. Cada funcionalidade começou com um teste que falhava.

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
| 9 | Relatório e slides | Estrutura e redação | Texto e organização | Toda afirmação sem número foi trocada por valor de `evidencias/results.json` e `detection.json` | Conferência manual de cada número com os JSONs da execução de 11/11/2026 |

## Princípio

Nenhuma resposta da IA foi aceita sem execução. Os casos 5, 6 e 8 são erros reais da IA, encontrados pela evidência (teste ou execução completa) e corrigidos antes da entrega. A responsabilidade pela adoção, pelo descarte e pela validação ficou com a equipe, que deve revisar este material antes da apresentação.
