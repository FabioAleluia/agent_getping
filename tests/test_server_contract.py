"""Valida regras reais de receber_agente em SQLite em memória, sem iniciar o servidor.

Opcional: GETPING_SERVER_SOURCE=/caminho/getping python -m unittest discover -s tests
Só o corpo da função é carregado; configuração, licença e aplicação de métricas
são substituídas por fixtures. Não é um teste da aplicação Flask completa.
"""
import ast
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import sys
import types
import unittest
from unittest.mock import Mock, patch

from test_agent import agent, CONFIG, IDENTIDADE

SOURCE = os.environ.get("GETPING_SERVER_SOURCE")


@unittest.skipUnless(SOURCE, "Defina GETPING_SERVER_SOURCE para validar o servidor local")
class ServerContractTests(unittest.TestCase):
    def setUp(self):
        arquivo = Path(SOURCE) / "getping/monitoring/persistence.py"
        arvore = ast.parse(arquivo.read_text(encoding="utf-8"))
        funcao = next(n for n in arvore.body if isinstance(n, ast.FunctionDef) and n.name == "receber_agente")
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript('''
            CREATE TABLE agent_tokens(id INTEGER PRIMARY KEY, ativo INTEGER);
            INSERT INTO agent_tokens VALUES(1,1);
            INSERT INTO agent_tokens VALUES(2,1);
            CREATE TABLE hosts(id INTEGER PRIMARY KEY, tipo_host TEXT, hostname TEXT,
                uuid_machine TEXT, empresa_id INTEGER, agent_boot_id TEXT, agent_sequence INTEGER,
                last_measurement TEXT, user_login TEXT, ip_dns TEXT, system_version TEXT, last_seen TEXT);
            CREATE TABLE agente_identidades(token_id INTEGER PRIMARY KEY, host_id INTEGER UNIQUE);
            CREATE TABLE agente_boots(host_id INTEGER, boot_id TEXT);
        ''')
        def ler_data(valor):
            return datetime.fromisoformat(valor)
        ns = {"timestamp": lambda valor=None: (valor or datetime.now(timezone.utc)).isoformat(),
              "ler_data": ler_data, "agora_utc": lambda: datetime.now(timezone.utc),
              "configuracao_atual": lambda: {"AGENT_TIMEOUT_SECONDS": 120},
              "Resultado": Mock(), "conectar": lambda: self.db, "_aplicar": Mock()}
        exec(compile(ast.Module(body=[funcao], type_ignores=[]), str(arquivo), "exec"), ns)
        self.receber = ns["receber_agente"]
        modulo = types.ModuleType("getping.db.licenses")
        modulo.pode_conectar_mais_agentes = lambda **kwargs: (True, "ok")
        contexto = patch.dict(sys.modules, {"getping.db.licenses": modulo})
        contexto.start()
        self.addCleanup(contexto.stop)
        self.agente = agent.Agente(CONFIG)
        self.agente.identidade = IDENTIDADE
        self.addCleanup(self.agente.close)
        with patch.object(agent, "get_system_operacional", return_value="Windows"), \
                patch.object(agent, "get_rede", return_value=("10.0.0.2", "10.0.0.1")), \
                patch.object(agent, "get_user_logon", return_value="usuario"), \
                patch.object(agent, "fazer_ping", return_value=(True, 1)):
            self.payload = self.agente.coletar()
        p = self.payload
        self.dados = {**p, "user_login": p["user_logon"], "ip_dns": p["ip_local"],
                      "system_version": p["system_operacional"]}

    def enviar(self, token=1, sequencia=True):
        p = self.payload
        return self.receber(self.dados, token, p["medido_em"],
                            p["sequencia"] if sequencia else None,
                            p["boot_id"] if sequencia else None)

    def test_payload_atual_aceito_e_repeticao_descartada(self):
        self.assertTrue(self.enviar()[1])
        self.assertFalse(self.enviar()[1])

    def test_host_legado_exige_vinculo_administrativo(self):
        self.db.execute("INSERT INTO hosts(tipo_host,hostname,uuid_machine) VALUES('agent','pc',?)", (IDENTIDADE,))
        self.db.commit()
        with self.assertRaisesRegex(PermissionError, "Host legado"):
            self.enviar()

    def test_token_compartilhado_e_recusado(self):
        self.enviar()
        self.dados["machine_uuid"] = "outro-dispositivo"
        with self.assertRaisesRegex(PermissionError, "outro dispositivo"):
            self.enviar()

    def test_payload_antigo_recusado_apos_uso_de_sequencia(self):
        self.enviar()
        with self.assertRaisesRegex(ValueError, "boot_id e sequencia"):
            self.enviar(sequencia=False)
