-= Sentinela Zero Trust =-

Este software implementa proteção de execução em tempo real contra programas maliciosos e virus de computador utilizando o clamav,
regras yara customizadas e checagem ostensiva do certificado diginal dos arquivos executáveis e dll no momento em que são iniciadas,
prevenindo assim que codigo não auditado possa executar no sistema operacional windows 10.

Para isso é utilzado um driver de kernel que intercepta o processo de execução das bibliotecas dinâmicas (dlls) e executaveis (.exe),
permitindo que um daemon rodando em python possa realizar as checagens de segurança e liberando a execução do arquivo em questão caso
ele esteja livre de ameaças.

Nos subdiretório SentinelaWDMDriver esta o codigo fonte do driver compilavel utilizando visual studio 2022 e wdk 10.0.26100.0, o no
subdiretório Sentinele_gui o codigo fonte em python para o daemon e interface de usuário.
